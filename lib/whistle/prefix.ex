defmodule Whistle.Prefix do
  @id_to_name %{
       0 => MumbleProto.Version,
       1 => MumbleProto.UDPTunnel,
       2 => MumbleProto.Authenticate,
       3 => MumbleProto.Ping,
       4 => MumbleProto.Reject,
       5 => MumbleProto.ServerSync,
       6 => MumbleProto.ChannelRemove,
       7 => MumbleProto.ChannelState,
       8 => MumbleProto.UserRemove,
       9 => MumbleProto.UserState,
      10 => MumbleProto.BanList,
      11 => MumbleProto.TextMessage,
      12 => MumbleProto.PermissionDenied,
      13 => MumbleProto.ACL,
      14 => MumbleProto.QueryUsers,
      15 => MumbleProto.CryptSetup,
      16 => MumbleProto.ContextActionModify,
      17 => MumbleProto.ContextAction,
      18 => MumbleProto.UserList,
      19 => MumbleProto.VoiceTarget,
      20 => MumbleProto.PermissionQuery,
      21 => MumbleProto.CodecVersion,
      22 => MumbleProto.UserStats,
      23 => MumbleProto.RequestBlob,
      24 => MumbleProto.ServerConfig,
      25 => MumbleProto.SuggestConfig
  }

  @name_to_id %{
      MumbleProto.Version => 0,
      MumbleProto.UDPTunnel => 1,
      MumbleProto.Authenticate => 2,
      MumbleProto.Ping => 3,
      MumbleProto.Reject => 4,
      MumbleProto.ServerSync => 5,
      MumbleProto.ChannelRemove => 6,
      MumbleProto.ChannelState => 7,
      MumbleProto.UserRemove => 8,
      MumbleProto.UserState => 9,
      MumbleProto.BanList => 10,
      MumbleProto.TextMessage => 11,
      MumbleProto.PermissionDenied => 12,
      MumbleProto.ACL => 13,
      MumbleProto.QueryUsers => 14,
      MumbleProto.CryptSetup => 15,
      MumbleProto.ContextActionModify => 16,
      MumbleProto.ContextAction => 17,
      MumbleProto.UserList => 18,
      MumbleProto.VoiceTarget => 19,
      MumbleProto.PermissionQuery => 20,
      MumbleProto.CodecVersion => 21,
      MumbleProto.UserStats => 22,
      MumbleProto.RequestBlob => 23,
      MumbleProto.ServerConfig => 24,
      MumbleProto.SuggestConfig => 25
  }

  def decode(packet, _opts \\ []) do
    #IO.inspect(packet, label: "Raw")
    <<type::16-big, length::32-big, payload::binary>> = packet
    # there could be excess garbage at the end confusing protobuf
    payload_truncated = :binary.part(payload, 0, length)
    #IO.inspect(length, label: "claimed length")
    #IO.inspect(byte_size(payload), label: "payload size")
    #true = (length == byte_size(payload))
    #IO.inspect(type, label: "Decode Type")
    module = Map.get(@id_to_name, type)
    if module == MumbleProto.UDPTunnel do
      # It appears the UDPTunnel isn't Protobuf (marked as unused)
      # but just using the prefixing system anyways
      MumbleProto.UDPTunnel.new(%{packet: payload})
    else
      #IO.inspect(module, label: "Decode Type (Module)")
      module.decode(payload_truncated)
    end
  end

  # Still special
  def encode(_, _opts \\ [])
  
  def encode(%MumbleProto.UDPTunnel{packet: payload}, _opts) do
    length = byte_size(payload)
    <<1::16-big, length::32-big, payload::binary>>
  end

  def encode(packet, _opts) do
    module = packet.__struct__
    #IO.inspect(module, label: "Encode Type")
    type = Map.get(@name_to_id, module)
    encoded = module.encode(packet)
    #IO.inspect(encoded, label: "Encoded Payload")
    length = byte_size(encoded)
    #IO.inspect(length, label: "Encoded Length")
    <<type::16-big, length::32-big, encoded::binary>>
  end
end
