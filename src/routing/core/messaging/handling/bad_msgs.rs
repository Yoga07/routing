// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::net::SocketAddr;

use super::Core;
use crate::{
    messages::{Message, MessageHash, Variant},
    peer::Peer,
    routing::command::Command,
    Error, Result,
};
use bytes::Bytes;
use sn_messaging::{DestInfo, DstLocation};

// Bad msgs
impl Core {
    /// Handle message whose trust we can't establish because its proof contains only keys we don't
    /// know.
    pub(crate) fn handle_untrusted_message(
        &self,
        sender: Option<SocketAddr>,
        msg: Message,
        received_dest_info: DestInfo,
    ) -> Result<Command> {
        let src_name = msg.src().name();
        let bounce_dst_key = *self.section_key_by_name(&src_name);
        let dest_info = DestInfo {
            dest: src_name,
            dest_section_pk: bounce_dst_key,
        };
        let bounce_msg = Message::single_src(
            &self.node,
            DstLocation::Direct,
            Variant::BouncedUntrustedMessage {
                msg: Box::new(msg),
                dest_info: received_dest_info,
            },
            None,
        )?;
        let bounce_msg = bounce_msg.to_bytes();

        if let Some(sender) = sender {
            Ok(Command::send_message_to_node(
                (sender, src_name),
                bounce_msg,
                dest_info,
            ))
        } else {
            Ok(self.send_message_to_our_elders(bounce_msg))
        }
    }

    /// Handle message that is "unknown" because we are not in the correct state (e.g. we are adult
    /// and the message is for elders). We bounce the message to our elders who have more
    /// information to decide what to do with it.
    pub(crate) fn handle_unknown_message(
        &self,
        sender: Option<SocketAddr>,
        msg_bytes: Bytes,
    ) -> Result<Command> {
        let src_key = *self.section.chain().last_key();
        let bounce_msg = Message::single_src(
            &self.node,
            DstLocation::Direct,
            Variant::BouncedUnknownMessage {
                src_key,
                message: msg_bytes,
            },
            None,
        )?;
        let bounce_msg = bounce_msg.to_bytes();

        // If the message came from one of our elders then bounce it only to them to avoid message
        // explosion.
        let our_elder_sender = sender.filter(|sender| {
            self.section
                .authority_provider()
                .peers()
                .any(|peer| peer.addr() == sender)
        });

        let dest_info = DestInfo {
            dest: self.section.prefix().name(),
            dest_section_pk: src_key,
        };

        if let Some(sender) = our_elder_sender {
            Ok(Command::send_message_to_node(
                (sender, self.section.prefix().name()),
                bounce_msg,
                dest_info,
            ))
        } else {
            Ok(self.send_message_to_our_elders(bounce_msg))
        }
    }

    pub(crate) fn handle_bounced_untrusted_message(
        &self,
        sender: Peer,
        dst_key: bls::PublicKey,
        bounced_msg: Message,
    ) -> Result<Command> {
        let span = trace_span!("Received BouncedUntrustedMessage", ?bounced_msg, %sender);
        let _span_guard = span.enter();

        let resend_msg = match bounced_msg.variant() {
            Variant::Sync { section, network } => {
                // `Sync` messages are handled specially, because they don't carry a proof chain.
                // Instead we use the section chain that's part of the included `Section` struct.
                // Problem is we can't extend that chain as it would invalidate the signature. We
                // must construct a new message instead.
                let section = section
                    .extend_chain(&dst_key, self.section.chain())
                    .map_err(|err| {
                        error!("extending section chain failed: {:?}", err);
                        Error::InvalidMessage // TODO: more specific error
                    })?;

                Message::single_src(
                    &self.node,
                    DstLocation::Direct,
                    Variant::Sync {
                        section,
                        network: network.clone(),
                    },
                    None,
                )?
            }
            _ => bounced_msg
                .extend_proof_chain(&dst_key, self.section.chain())
                .map_err(|err| {
                    error!("extending proof chain failed: {:?}", err);
                    Error::InvalidMessage // TODO: more specific error
                })?,
        };

        let dest_info = DestInfo {
            dest: *sender.name(),
            dest_section_pk: dst_key,
        };
        trace!("resending with extended proof");
        Ok(Command::send_message_to_node(
            (*sender.addr(), *sender.name()),
            resend_msg.to_bytes(),
            dest_info,
        ))
    }

    pub(crate) fn handle_bounced_unknown_message(
        &self,
        sender: Peer,
        bounced_msg_bytes: Bytes,
        sender_last_key: &bls::PublicKey,
    ) -> Result<Vec<Command>> {
        let span = trace_span!(
            "Received BouncedUnknownMessage",
            bounced_msg_hash=?MessageHash::from_bytes(&bounced_msg_bytes),
            %sender
        );
        let _span_guard = span.enter();

        if !self.section.prefix().matches(sender.name()) {
            trace!("peer is not from our section, discarding");
            return Ok(vec![]);
        }

        if !self.section.chain().has_key(sender_last_key)
            || sender_last_key == self.section.chain().last_key()
        {
            trace!("peer is up to date or ahead of us, discarding");
            return Ok(vec![]);
        }

        trace!("peer is lagging behind, resending with Sync",);
        // First send Sync to update the peer, then resend the message itself. If the messages
        // arrive in the same order they were sent, the Sync should update the peer so it will then
        // be able to handle the resent message. If not, the peer will bounce the message again.
        Ok(vec![
            self.send_direct_message(
                (*sender.addr(), *sender.name()),
                Variant::Sync {
                    section: self.section.clone(),
                    network: self.network.clone(),
                },
                *self.section.chain().last_key(),
            )?,
            Command::send_message_to_node(
                (*sender.addr(), *sender.name()),
                bounced_msg_bytes,
                DestInfo {
                    dest: *sender.name(),
                    dest_section_pk: *sender_last_key,
                },
            ),
        ])
    }
}
