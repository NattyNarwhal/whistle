defmodule MumbleProto.Reject.RejectType do
  @moduledoc false
  use Protobuf, enum: true, syntax: :proto2

  @type t ::
          integer
          | :None
          | :WrongVersion
          | :InvalidUsername
          | :WrongUserPW
          | :WrongServerPW
          | :UsernameInUse
          | :ServerFull
          | :NoCertificate
          | :AuthenticatorFail
  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.EnumDescriptorProto.decode(
      <<10, 10, 82, 101, 106, 101, 99, 116, 84, 121, 112, 101, 18, 8, 10, 4, 78, 111, 110, 101,
        16, 0, 18, 16, 10, 12, 87, 114, 111, 110, 103, 86, 101, 114, 115, 105, 111, 110, 16, 1,
        18, 19, 10, 15, 73, 110, 118, 97, 108, 105, 100, 85, 115, 101, 114, 110, 97, 109, 101, 16,
        2, 18, 15, 10, 11, 87, 114, 111, 110, 103, 85, 115, 101, 114, 80, 87, 16, 3, 18, 17, 10,
        13, 87, 114, 111, 110, 103, 83, 101, 114, 118, 101, 114, 80, 87, 16, 4, 18, 17, 10, 13,
        85, 115, 101, 114, 110, 97, 109, 101, 73, 110, 85, 115, 101, 16, 5, 18, 14, 10, 10, 83,
        101, 114, 118, 101, 114, 70, 117, 108, 108, 16, 6, 18, 17, 10, 13, 78, 111, 67, 101, 114,
        116, 105, 102, 105, 99, 97, 116, 101, 16, 7, 18, 21, 10, 17, 65, 117, 116, 104, 101, 110,
        116, 105, 99, 97, 116, 111, 114, 70, 97, 105, 108, 16, 8>>
    )
  end

  field :None, 0
  field :WrongVersion, 1
  field :InvalidUsername, 2
  field :WrongUserPW, 3
  field :WrongServerPW, 4
  field :UsernameInUse, 5
  field :ServerFull, 6
  field :NoCertificate, 7
  field :AuthenticatorFail, 8
end

defmodule MumbleProto.PermissionDenied.DenyType do
  @moduledoc false
  use Protobuf, enum: true, syntax: :proto2

  @type t ::
          integer
          | :Text
          | :Permission
          | :SuperUser
          | :ChannelName
          | :TextTooLong
          | :H9K
          | :TemporaryChannel
          | :MissingCertificate
          | :UserName
          | :ChannelFull
          | :NestingLimit
          | :ChannelCountLimit
          | :ChannelListenerLimit
          | :UserListenerLimit
  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.EnumDescriptorProto.decode(
      <<10, 8, 68, 101, 110, 121, 84, 121, 112, 101, 18, 8, 10, 4, 84, 101, 120, 116, 16, 0, 18,
        14, 10, 10, 80, 101, 114, 109, 105, 115, 115, 105, 111, 110, 16, 1, 18, 13, 10, 9, 83,
        117, 112, 101, 114, 85, 115, 101, 114, 16, 2, 18, 15, 10, 11, 67, 104, 97, 110, 110, 101,
        108, 78, 97, 109, 101, 16, 3, 18, 15, 10, 11, 84, 101, 120, 116, 84, 111, 111, 76, 111,
        110, 103, 16, 4, 18, 7, 10, 3, 72, 57, 75, 16, 5, 18, 20, 10, 16, 84, 101, 109, 112, 111,
        114, 97, 114, 121, 67, 104, 97, 110, 110, 101, 108, 16, 6, 18, 22, 10, 18, 77, 105, 115,
        115, 105, 110, 103, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 16, 7, 18, 12, 10,
        8, 85, 115, 101, 114, 78, 97, 109, 101, 16, 8, 18, 15, 10, 11, 67, 104, 97, 110, 110, 101,
        108, 70, 117, 108, 108, 16, 9, 18, 16, 10, 12, 78, 101, 115, 116, 105, 110, 103, 76, 105,
        109, 105, 116, 16, 10, 18, 21, 10, 17, 67, 104, 97, 110, 110, 101, 108, 67, 111, 117, 110,
        116, 76, 105, 109, 105, 116, 16, 11, 18, 24, 10, 20, 67, 104, 97, 110, 110, 101, 108, 76,
        105, 115, 116, 101, 110, 101, 114, 76, 105, 109, 105, 116, 16, 12, 18, 21, 10, 17, 85,
        115, 101, 114, 76, 105, 115, 116, 101, 110, 101, 114, 76, 105, 109, 105, 116, 16, 13>>
    )
  end

  field :Text, 0
  field :Permission, 1
  field :SuperUser, 2
  field :ChannelName, 3
  field :TextTooLong, 4
  field :H9K, 5
  field :TemporaryChannel, 6
  field :MissingCertificate, 7
  field :UserName, 8
  field :ChannelFull, 9
  field :NestingLimit, 10
  field :ChannelCountLimit, 11
  field :ChannelListenerLimit, 12
  field :UserListenerLimit, 13
end

defmodule MumbleProto.ContextActionModify.Context do
  @moduledoc false
  use Protobuf, enum: true, syntax: :proto2

  @type t :: integer | :Server | :Channel | :User
  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.EnumDescriptorProto.decode(
      <<10, 7, 67, 111, 110, 116, 101, 120, 116, 18, 10, 10, 6, 83, 101, 114, 118, 101, 114, 16,
        1, 18, 11, 10, 7, 67, 104, 97, 110, 110, 101, 108, 16, 2, 18, 8, 10, 4, 85, 115, 101, 114,
        16, 4>>
    )
  end

  field :Server, 1
  field :Channel, 2
  field :User, 4
end

defmodule MumbleProto.ContextActionModify.Operation do
  @moduledoc false
  use Protobuf, enum: true, syntax: :proto2

  @type t :: integer | :Add | :Remove
  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.EnumDescriptorProto.decode(
      <<10, 9, 79, 112, 101, 114, 97, 116, 105, 111, 110, 18, 7, 10, 3, 65, 100, 100, 16, 0, 18,
        10, 10, 6, 82, 101, 109, 111, 118, 101, 16, 1>>
    )
  end

  field :Add, 0
  field :Remove, 1
end

defmodule MumbleProto.Version do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          version: non_neg_integer,
          release: String.t(),
          os: String.t(),
          os_version: String.t()
        }
  defstruct [:version, :release, :os, :os_version]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 7, 86, 101, 114, 115, 105, 111, 110, 18, 24, 10, 7, 118, 101, 114, 115, 105, 111, 110,
        24, 1, 32, 1, 40, 13, 82, 7, 118, 101, 114, 115, 105, 111, 110, 18, 24, 10, 7, 114, 101,
        108, 101, 97, 115, 101, 24, 2, 32, 1, 40, 9, 82, 7, 114, 101, 108, 101, 97, 115, 101, 18,
        14, 10, 2, 111, 115, 24, 3, 32, 1, 40, 9, 82, 2, 111, 115, 18, 29, 10, 10, 111, 115, 95,
        118, 101, 114, 115, 105, 111, 110, 24, 4, 32, 1, 40, 9, 82, 9, 111, 115, 86, 101, 114,
        115, 105, 111, 110>>
    )
  end

  field :version, 1, optional: true, type: :uint32
  field :release, 2, optional: true, type: :string
  field :os, 3, optional: true, type: :string
  field :os_version, 4, optional: true, type: :string
end

defmodule MumbleProto.UDPTunnel do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          packet: binary
        }
  defstruct [:packet]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 9, 85, 68, 80, 84, 117, 110, 110, 101, 108, 18, 22, 10, 6, 112, 97, 99, 107, 101, 116,
        24, 1, 32, 2, 40, 12, 82, 6, 112, 97, 99, 107, 101, 116>>
    )
  end

  field :packet, 1, required: true, type: :bytes
end

defmodule MumbleProto.Authenticate do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          username: String.t(),
          password: String.t(),
          tokens: [String.t()],
          celt_versions: [integer],
          opus: boolean
        }
  defstruct [:username, :password, :tokens, :celt_versions, :opus]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 12, 65, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 101, 18, 26, 10, 8, 117, 115,
        101, 114, 110, 97, 109, 101, 24, 1, 32, 1, 40, 9, 82, 8, 117, 115, 101, 114, 110, 97, 109,
        101, 18, 26, 10, 8, 112, 97, 115, 115, 119, 111, 114, 100, 24, 2, 32, 1, 40, 9, 82, 8,
        112, 97, 115, 115, 119, 111, 114, 100, 18, 22, 10, 6, 116, 111, 107, 101, 110, 115, 24, 3,
        32, 3, 40, 9, 82, 6, 116, 111, 107, 101, 110, 115, 18, 35, 10, 13, 99, 101, 108, 116, 95,
        118, 101, 114, 115, 105, 111, 110, 115, 24, 4, 32, 3, 40, 5, 82, 12, 99, 101, 108, 116,
        86, 101, 114, 115, 105, 111, 110, 115, 18, 25, 10, 4, 111, 112, 117, 115, 24, 5, 32, 1,
        40, 8, 58, 5, 102, 97, 108, 115, 101, 82, 4, 111, 112, 117, 115>>
    )
  end

  field :username, 1, optional: true, type: :string
  field :password, 2, optional: true, type: :string
  field :tokens, 3, repeated: true, type: :string
  field :celt_versions, 4, repeated: true, type: :int32
  field :opus, 5, optional: true, type: :bool, default: false
end

defmodule MumbleProto.Ping do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          timestamp: non_neg_integer,
          good: non_neg_integer,
          late: non_neg_integer,
          lost: non_neg_integer,
          resync: non_neg_integer,
          udp_packets: non_neg_integer,
          tcp_packets: non_neg_integer,
          udp_ping_avg: float | :infinity | :negative_infinity | :nan,
          udp_ping_var: float | :infinity | :negative_infinity | :nan,
          tcp_ping_avg: float | :infinity | :negative_infinity | :nan,
          tcp_ping_var: float | :infinity | :negative_infinity | :nan
        }
  defstruct [
    :timestamp,
    :good,
    :late,
    :lost,
    :resync,
    :udp_packets,
    :tcp_packets,
    :udp_ping_avg,
    :udp_ping_var,
    :tcp_ping_avg,
    :tcp_ping_var
  ]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 4, 80, 105, 110, 103, 18, 28, 10, 9, 116, 105, 109, 101, 115, 116, 97, 109, 112, 24,
        1, 32, 1, 40, 4, 82, 9, 116, 105, 109, 101, 115, 116, 97, 109, 112, 18, 18, 10, 4, 103,
        111, 111, 100, 24, 2, 32, 1, 40, 13, 82, 4, 103, 111, 111, 100, 18, 18, 10, 4, 108, 97,
        116, 101, 24, 3, 32, 1, 40, 13, 82, 4, 108, 97, 116, 101, 18, 18, 10, 4, 108, 111, 115,
        116, 24, 4, 32, 1, 40, 13, 82, 4, 108, 111, 115, 116, 18, 22, 10, 6, 114, 101, 115, 121,
        110, 99, 24, 5, 32, 1, 40, 13, 82, 6, 114, 101, 115, 121, 110, 99, 18, 31, 10, 11, 117,
        100, 112, 95, 112, 97, 99, 107, 101, 116, 115, 24, 6, 32, 1, 40, 13, 82, 10, 117, 100,
        112, 80, 97, 99, 107, 101, 116, 115, 18, 31, 10, 11, 116, 99, 112, 95, 112, 97, 99, 107,
        101, 116, 115, 24, 7, 32, 1, 40, 13, 82, 10, 116, 99, 112, 80, 97, 99, 107, 101, 116, 115,
        18, 32, 10, 12, 117, 100, 112, 95, 112, 105, 110, 103, 95, 97, 118, 103, 24, 8, 32, 1, 40,
        2, 82, 10, 117, 100, 112, 80, 105, 110, 103, 65, 118, 103, 18, 32, 10, 12, 117, 100, 112,
        95, 112, 105, 110, 103, 95, 118, 97, 114, 24, 9, 32, 1, 40, 2, 82, 10, 117, 100, 112, 80,
        105, 110, 103, 86, 97, 114, 18, 32, 10, 12, 116, 99, 112, 95, 112, 105, 110, 103, 95, 97,
        118, 103, 24, 10, 32, 1, 40, 2, 82, 10, 116, 99, 112, 80, 105, 110, 103, 65, 118, 103, 18,
        32, 10, 12, 116, 99, 112, 95, 112, 105, 110, 103, 95, 118, 97, 114, 24, 11, 32, 1, 40, 2,
        82, 10, 116, 99, 112, 80, 105, 110, 103, 86, 97, 114>>
    )
  end

  field :timestamp, 1, optional: true, type: :uint64
  field :good, 2, optional: true, type: :uint32
  field :late, 3, optional: true, type: :uint32
  field :lost, 4, optional: true, type: :uint32
  field :resync, 5, optional: true, type: :uint32
  field :udp_packets, 6, optional: true, type: :uint32
  field :tcp_packets, 7, optional: true, type: :uint32
  field :udp_ping_avg, 8, optional: true, type: :float
  field :udp_ping_var, 9, optional: true, type: :float
  field :tcp_ping_avg, 10, optional: true, type: :float
  field :tcp_ping_var, 11, optional: true, type: :float
end

defmodule MumbleProto.Reject do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          type: MumbleProto.Reject.RejectType.t(),
          reason: String.t()
        }
  defstruct [:type, :reason]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 6, 82, 101, 106, 101, 99, 116, 18, 50, 10, 4, 116, 121, 112, 101, 24, 1, 32, 1, 40,
        14, 50, 30, 46, 77, 117, 109, 98, 108, 101, 80, 114, 111, 116, 111, 46, 82, 101, 106, 101,
        99, 116, 46, 82, 101, 106, 101, 99, 116, 84, 121, 112, 101, 82, 4, 116, 121, 112, 101, 18,
        22, 10, 6, 114, 101, 97, 115, 111, 110, 24, 2, 32, 1, 40, 9, 82, 6, 114, 101, 97, 115,
        111, 110, 34, 174, 1, 10, 10, 82, 101, 106, 101, 99, 116, 84, 121, 112, 101, 18, 8, 10, 4,
        78, 111, 110, 101, 16, 0, 18, 16, 10, 12, 87, 114, 111, 110, 103, 86, 101, 114, 115, 105,
        111, 110, 16, 1, 18, 19, 10, 15, 73, 110, 118, 97, 108, 105, 100, 85, 115, 101, 114, 110,
        97, 109, 101, 16, 2, 18, 15, 10, 11, 87, 114, 111, 110, 103, 85, 115, 101, 114, 80, 87,
        16, 3, 18, 17, 10, 13, 87, 114, 111, 110, 103, 83, 101, 114, 118, 101, 114, 80, 87, 16, 4,
        18, 17, 10, 13, 85, 115, 101, 114, 110, 97, 109, 101, 73, 110, 85, 115, 101, 16, 5, 18,
        14, 10, 10, 83, 101, 114, 118, 101, 114, 70, 117, 108, 108, 16, 6, 18, 17, 10, 13, 78,
        111, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 16, 7, 18, 21, 10, 17, 65, 117,
        116, 104, 101, 110, 116, 105, 99, 97, 116, 111, 114, 70, 97, 105, 108, 16, 8>>
    )
  end

  field :type, 1, optional: true, type: MumbleProto.Reject.RejectType, enum: true
  field :reason, 2, optional: true, type: :string
end

defmodule MumbleProto.ServerSync do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          session: non_neg_integer,
          max_bandwidth: non_neg_integer,
          welcome_text: String.t(),
          permissions: non_neg_integer
        }
  defstruct [:session, :max_bandwidth, :welcome_text, :permissions]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 10, 83, 101, 114, 118, 101, 114, 83, 121, 110, 99, 18, 24, 10, 7, 115, 101, 115, 115,
        105, 111, 110, 24, 1, 32, 1, 40, 13, 82, 7, 115, 101, 115, 115, 105, 111, 110, 18, 35, 10,
        13, 109, 97, 120, 95, 98, 97, 110, 100, 119, 105, 100, 116, 104, 24, 2, 32, 1, 40, 13, 82,
        12, 109, 97, 120, 66, 97, 110, 100, 119, 105, 100, 116, 104, 18, 33, 10, 12, 119, 101,
        108, 99, 111, 109, 101, 95, 116, 101, 120, 116, 24, 3, 32, 1, 40, 9, 82, 11, 119, 101,
        108, 99, 111, 109, 101, 84, 101, 120, 116, 18, 32, 10, 11, 112, 101, 114, 109, 105, 115,
        115, 105, 111, 110, 115, 24, 4, 32, 1, 40, 4, 82, 11, 112, 101, 114, 109, 105, 115, 115,
        105, 111, 110, 115>>
    )
  end

  field :session, 1, optional: true, type: :uint32
  field :max_bandwidth, 2, optional: true, type: :uint32
  field :welcome_text, 3, optional: true, type: :string
  field :permissions, 4, optional: true, type: :uint64
end

defmodule MumbleProto.ChannelRemove do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          channel_id: non_neg_integer
        }
  defstruct [:channel_id]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 13, 67, 104, 97, 110, 110, 101, 108, 82, 101, 109, 111, 118, 101, 18, 29, 10, 10, 99,
        104, 97, 110, 110, 101, 108, 95, 105, 100, 24, 1, 32, 2, 40, 13, 82, 9, 99, 104, 97, 110,
        110, 101, 108, 73, 100>>
    )
  end

  field :channel_id, 1, required: true, type: :uint32
end

defmodule MumbleProto.ChannelState do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          channel_id: non_neg_integer,
          parent: non_neg_integer,
          name: String.t(),
          links: [non_neg_integer],
          description: String.t(),
          links_add: [non_neg_integer],
          links_remove: [non_neg_integer],
          temporary: boolean,
          position: integer,
          description_hash: binary,
          max_users: non_neg_integer,
          is_enter_restricted: boolean,
          can_enter: boolean
        }
  defstruct [
    :channel_id,
    :parent,
    :name,
    :links,
    :description,
    :links_add,
    :links_remove,
    :temporary,
    :position,
    :description_hash,
    :max_users,
    :is_enter_restricted,
    :can_enter
  ]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 12, 67, 104, 97, 110, 110, 101, 108, 83, 116, 97, 116, 101, 18, 29, 10, 10, 99, 104,
        97, 110, 110, 101, 108, 95, 105, 100, 24, 1, 32, 1, 40, 13, 82, 9, 99, 104, 97, 110, 110,
        101, 108, 73, 100, 18, 22, 10, 6, 112, 97, 114, 101, 110, 116, 24, 2, 32, 1, 40, 13, 82,
        6, 112, 97, 114, 101, 110, 116, 18, 18, 10, 4, 110, 97, 109, 101, 24, 3, 32, 1, 40, 9, 82,
        4, 110, 97, 109, 101, 18, 20, 10, 5, 108, 105, 110, 107, 115, 24, 4, 32, 3, 40, 13, 82, 5,
        108, 105, 110, 107, 115, 18, 32, 10, 11, 100, 101, 115, 99, 114, 105, 112, 116, 105, 111,
        110, 24, 5, 32, 1, 40, 9, 82, 11, 100, 101, 115, 99, 114, 105, 112, 116, 105, 111, 110,
        18, 27, 10, 9, 108, 105, 110, 107, 115, 95, 97, 100, 100, 24, 6, 32, 3, 40, 13, 82, 8,
        108, 105, 110, 107, 115, 65, 100, 100, 18, 33, 10, 12, 108, 105, 110, 107, 115, 95, 114,
        101, 109, 111, 118, 101, 24, 7, 32, 3, 40, 13, 82, 11, 108, 105, 110, 107, 115, 82, 101,
        109, 111, 118, 101, 18, 35, 10, 9, 116, 101, 109, 112, 111, 114, 97, 114, 121, 24, 8, 32,
        1, 40, 8, 58, 5, 102, 97, 108, 115, 101, 82, 9, 116, 101, 109, 112, 111, 114, 97, 114,
        121, 18, 29, 10, 8, 112, 111, 115, 105, 116, 105, 111, 110, 24, 9, 32, 1, 40, 5, 58, 1,
        48, 82, 8, 112, 111, 115, 105, 116, 105, 111, 110, 18, 41, 10, 16, 100, 101, 115, 99, 114,
        105, 112, 116, 105, 111, 110, 95, 104, 97, 115, 104, 24, 10, 32, 1, 40, 12, 82, 15, 100,
        101, 115, 99, 114, 105, 112, 116, 105, 111, 110, 72, 97, 115, 104, 18, 27, 10, 9, 109, 97,
        120, 95, 117, 115, 101, 114, 115, 24, 11, 32, 1, 40, 13, 82, 8, 109, 97, 120, 85, 115,
        101, 114, 115, 18, 46, 10, 19, 105, 115, 95, 101, 110, 116, 101, 114, 95, 114, 101, 115,
        116, 114, 105, 99, 116, 101, 100, 24, 12, 32, 1, 40, 8, 82, 17, 105, 115, 69, 110, 116,
        101, 114, 82, 101, 115, 116, 114, 105, 99, 116, 101, 100, 18, 27, 10, 9, 99, 97, 110, 95,
        101, 110, 116, 101, 114, 24, 13, 32, 1, 40, 8, 82, 8, 99, 97, 110, 69, 110, 116, 101,
        114>>
    )
  end

  field :channel_id, 1, optional: true, type: :uint32
  field :parent, 2, optional: true, type: :uint32
  field :name, 3, optional: true, type: :string
  field :links, 4, repeated: true, type: :uint32
  field :description, 5, optional: true, type: :string
  field :links_add, 6, repeated: true, type: :uint32
  field :links_remove, 7, repeated: true, type: :uint32
  field :temporary, 8, optional: true, type: :bool, default: false
  field :position, 9, optional: true, type: :int32, default: 0
  field :description_hash, 10, optional: true, type: :bytes
  field :max_users, 11, optional: true, type: :uint32
  field :is_enter_restricted, 12, optional: true, type: :bool
  field :can_enter, 13, optional: true, type: :bool
end

defmodule MumbleProto.UserRemove do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          session: non_neg_integer,
          actor: non_neg_integer,
          reason: String.t(),
          ban: boolean
        }
  defstruct [:session, :actor, :reason, :ban]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 10, 85, 115, 101, 114, 82, 101, 109, 111, 118, 101, 18, 24, 10, 7, 115, 101, 115, 115,
        105, 111, 110, 24, 1, 32, 2, 40, 13, 82, 7, 115, 101, 115, 115, 105, 111, 110, 18, 20, 10,
        5, 97, 99, 116, 111, 114, 24, 2, 32, 1, 40, 13, 82, 5, 97, 99, 116, 111, 114, 18, 22, 10,
        6, 114, 101, 97, 115, 111, 110, 24, 3, 32, 1, 40, 9, 82, 6, 114, 101, 97, 115, 111, 110,
        18, 16, 10, 3, 98, 97, 110, 24, 4, 32, 1, 40, 8, 82, 3, 98, 97, 110>>
    )
  end

  field :session, 1, required: true, type: :uint32
  field :actor, 2, optional: true, type: :uint32
  field :reason, 3, optional: true, type: :string
  field :ban, 4, optional: true, type: :bool
end

defmodule MumbleProto.UserState do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          session: non_neg_integer,
          actor: non_neg_integer,
          name: String.t(),
          user_id: non_neg_integer,
          channel_id: non_neg_integer,
          mute: boolean,
          deaf: boolean,
          suppress: boolean,
          self_mute: boolean,
          self_deaf: boolean,
          texture: binary,
          plugin_context: binary,
          plugin_identity: String.t(),
          comment: String.t(),
          hash: String.t(),
          comment_hash: binary,
          texture_hash: binary,
          priority_speaker: boolean,
          recording: boolean,
          temporary_access_tokens: [String.t()],
          listening_channel_add: [non_neg_integer],
          listening_channel_remove: [non_neg_integer]
        }
  defstruct [
    :session,
    :actor,
    :name,
    :user_id,
    :channel_id,
    :mute,
    :deaf,
    :suppress,
    :self_mute,
    :self_deaf,
    :texture,
    :plugin_context,
    :plugin_identity,
    :comment,
    :hash,
    :comment_hash,
    :texture_hash,
    :priority_speaker,
    :recording,
    :temporary_access_tokens,
    :listening_channel_add,
    :listening_channel_remove
  ]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 9, 85, 115, 101, 114, 83, 116, 97, 116, 101, 18, 24, 10, 7, 115, 101, 115, 115, 105,
        111, 110, 24, 1, 32, 1, 40, 13, 82, 7, 115, 101, 115, 115, 105, 111, 110, 18, 20, 10, 5,
        97, 99, 116, 111, 114, 24, 2, 32, 1, 40, 13, 82, 5, 97, 99, 116, 111, 114, 18, 18, 10, 4,
        110, 97, 109, 101, 24, 3, 32, 1, 40, 9, 82, 4, 110, 97, 109, 101, 18, 23, 10, 7, 117, 115,
        101, 114, 95, 105, 100, 24, 4, 32, 1, 40, 13, 82, 6, 117, 115, 101, 114, 73, 100, 18, 29,
        10, 10, 99, 104, 97, 110, 110, 101, 108, 95, 105, 100, 24, 5, 32, 1, 40, 13, 82, 9, 99,
        104, 97, 110, 110, 101, 108, 73, 100, 18, 18, 10, 4, 109, 117, 116, 101, 24, 6, 32, 1, 40,
        8, 82, 4, 109, 117, 116, 101, 18, 18, 10, 4, 100, 101, 97, 102, 24, 7, 32, 1, 40, 8, 82,
        4, 100, 101, 97, 102, 18, 26, 10, 8, 115, 117, 112, 112, 114, 101, 115, 115, 24, 8, 32, 1,
        40, 8, 82, 8, 115, 117, 112, 112, 114, 101, 115, 115, 18, 27, 10, 9, 115, 101, 108, 102,
        95, 109, 117, 116, 101, 24, 9, 32, 1, 40, 8, 82, 8, 115, 101, 108, 102, 77, 117, 116, 101,
        18, 27, 10, 9, 115, 101, 108, 102, 95, 100, 101, 97, 102, 24, 10, 32, 1, 40, 8, 82, 8,
        115, 101, 108, 102, 68, 101, 97, 102, 18, 24, 10, 7, 116, 101, 120, 116, 117, 114, 101,
        24, 11, 32, 1, 40, 12, 82, 7, 116, 101, 120, 116, 117, 114, 101, 18, 37, 10, 14, 112, 108,
        117, 103, 105, 110, 95, 99, 111, 110, 116, 101, 120, 116, 24, 12, 32, 1, 40, 12, 82, 13,
        112, 108, 117, 103, 105, 110, 67, 111, 110, 116, 101, 120, 116, 18, 39, 10, 15, 112, 108,
        117, 103, 105, 110, 95, 105, 100, 101, 110, 116, 105, 116, 121, 24, 13, 32, 1, 40, 9, 82,
        14, 112, 108, 117, 103, 105, 110, 73, 100, 101, 110, 116, 105, 116, 121, 18, 24, 10, 7,
        99, 111, 109, 109, 101, 110, 116, 24, 14, 32, 1, 40, 9, 82, 7, 99, 111, 109, 109, 101,
        110, 116, 18, 18, 10, 4, 104, 97, 115, 104, 24, 15, 32, 1, 40, 9, 82, 4, 104, 97, 115,
        104, 18, 33, 10, 12, 99, 111, 109, 109, 101, 110, 116, 95, 104, 97, 115, 104, 24, 16, 32,
        1, 40, 12, 82, 11, 99, 111, 109, 109, 101, 110, 116, 72, 97, 115, 104, 18, 33, 10, 12,
        116, 101, 120, 116, 117, 114, 101, 95, 104, 97, 115, 104, 24, 17, 32, 1, 40, 12, 82, 11,
        116, 101, 120, 116, 117, 114, 101, 72, 97, 115, 104, 18, 41, 10, 16, 112, 114, 105, 111,
        114, 105, 116, 121, 95, 115, 112, 101, 97, 107, 101, 114, 24, 18, 32, 1, 40, 8, 82, 15,
        112, 114, 105, 111, 114, 105, 116, 121, 83, 112, 101, 97, 107, 101, 114, 18, 28, 10, 9,
        114, 101, 99, 111, 114, 100, 105, 110, 103, 24, 19, 32, 1, 40, 8, 82, 9, 114, 101, 99,
        111, 114, 100, 105, 110, 103, 18, 54, 10, 23, 116, 101, 109, 112, 111, 114, 97, 114, 121,
        95, 97, 99, 99, 101, 115, 115, 95, 116, 111, 107, 101, 110, 115, 24, 20, 32, 3, 40, 9, 82,
        21, 116, 101, 109, 112, 111, 114, 97, 114, 121, 65, 99, 99, 101, 115, 115, 84, 111, 107,
        101, 110, 115, 18, 50, 10, 21, 108, 105, 115, 116, 101, 110, 105, 110, 103, 95, 99, 104,
        97, 110, 110, 101, 108, 95, 97, 100, 100, 24, 21, 32, 3, 40, 13, 82, 19, 108, 105, 115,
        116, 101, 110, 105, 110, 103, 67, 104, 97, 110, 110, 101, 108, 65, 100, 100, 18, 56, 10,
        24, 108, 105, 115, 116, 101, 110, 105, 110, 103, 95, 99, 104, 97, 110, 110, 101, 108, 95,
        114, 101, 109, 111, 118, 101, 24, 22, 32, 3, 40, 13, 82, 22, 108, 105, 115, 116, 101, 110,
        105, 110, 103, 67, 104, 97, 110, 110, 101, 108, 82, 101, 109, 111, 118, 101>>
    )
  end

  field :session, 1, optional: true, type: :uint32
  field :actor, 2, optional: true, type: :uint32
  field :name, 3, optional: true, type: :string
  field :user_id, 4, optional: true, type: :uint32
  field :channel_id, 5, optional: true, type: :uint32
  field :mute, 6, optional: true, type: :bool
  field :deaf, 7, optional: true, type: :bool
  field :suppress, 8, optional: true, type: :bool
  field :self_mute, 9, optional: true, type: :bool
  field :self_deaf, 10, optional: true, type: :bool
  field :texture, 11, optional: true, type: :bytes
  field :plugin_context, 12, optional: true, type: :bytes
  field :plugin_identity, 13, optional: true, type: :string
  field :comment, 14, optional: true, type: :string
  field :hash, 15, optional: true, type: :string
  field :comment_hash, 16, optional: true, type: :bytes
  field :texture_hash, 17, optional: true, type: :bytes
  field :priority_speaker, 18, optional: true, type: :bool
  field :recording, 19, optional: true, type: :bool
  field :temporary_access_tokens, 20, repeated: true, type: :string
  field :listening_channel_add, 21, repeated: true, type: :uint32
  field :listening_channel_remove, 22, repeated: true, type: :uint32
end

defmodule MumbleProto.BanList.BanEntry do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          address: binary,
          mask: non_neg_integer,
          name: String.t(),
          hash: String.t(),
          reason: String.t(),
          start: String.t(),
          duration: non_neg_integer
        }
  defstruct [:address, :mask, :name, :hash, :reason, :start, :duration]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 8, 66, 97, 110, 69, 110, 116, 114, 121, 18, 24, 10, 7, 97, 100, 100, 114, 101, 115,
        115, 24, 1, 32, 2, 40, 12, 82, 7, 97, 100, 100, 114, 101, 115, 115, 18, 18, 10, 4, 109,
        97, 115, 107, 24, 2, 32, 2, 40, 13, 82, 4, 109, 97, 115, 107, 18, 18, 10, 4, 110, 97, 109,
        101, 24, 3, 32, 1, 40, 9, 82, 4, 110, 97, 109, 101, 18, 18, 10, 4, 104, 97, 115, 104, 24,
        4, 32, 1, 40, 9, 82, 4, 104, 97, 115, 104, 18, 22, 10, 6, 114, 101, 97, 115, 111, 110, 24,
        5, 32, 1, 40, 9, 82, 6, 114, 101, 97, 115, 111, 110, 18, 20, 10, 5, 115, 116, 97, 114,
        116, 24, 6, 32, 1, 40, 9, 82, 5, 115, 116, 97, 114, 116, 18, 26, 10, 8, 100, 117, 114, 97,
        116, 105, 111, 110, 24, 7, 32, 1, 40, 13, 82, 8, 100, 117, 114, 97, 116, 105, 111, 110>>
    )
  end

  field :address, 1, required: true, type: :bytes
  field :mask, 2, required: true, type: :uint32
  field :name, 3, optional: true, type: :string
  field :hash, 4, optional: true, type: :string
  field :reason, 5, optional: true, type: :string
  field :start, 6, optional: true, type: :string
  field :duration, 7, optional: true, type: :uint32
end

defmodule MumbleProto.BanList do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          bans: [MumbleProto.BanList.BanEntry.t()],
          query: boolean
        }
  defstruct [:bans, :query]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 7, 66, 97, 110, 76, 105, 115, 116, 18, 49, 10, 4, 98, 97, 110, 115, 24, 1, 32, 3, 40,
        11, 50, 29, 46, 77, 117, 109, 98, 108, 101, 80, 114, 111, 116, 111, 46, 66, 97, 110, 76,
        105, 115, 116, 46, 66, 97, 110, 69, 110, 116, 114, 121, 82, 4, 98, 97, 110, 115, 18, 27,
        10, 5, 113, 117, 101, 114, 121, 24, 2, 32, 1, 40, 8, 58, 5, 102, 97, 108, 115, 101, 82, 5,
        113, 117, 101, 114, 121, 26, 170, 1, 10, 8, 66, 97, 110, 69, 110, 116, 114, 121, 18, 24,
        10, 7, 97, 100, 100, 114, 101, 115, 115, 24, 1, 32, 2, 40, 12, 82, 7, 97, 100, 100, 114,
        101, 115, 115, 18, 18, 10, 4, 109, 97, 115, 107, 24, 2, 32, 2, 40, 13, 82, 4, 109, 97,
        115, 107, 18, 18, 10, 4, 110, 97, 109, 101, 24, 3, 32, 1, 40, 9, 82, 4, 110, 97, 109, 101,
        18, 18, 10, 4, 104, 97, 115, 104, 24, 4, 32, 1, 40, 9, 82, 4, 104, 97, 115, 104, 18, 22,
        10, 6, 114, 101, 97, 115, 111, 110, 24, 5, 32, 1, 40, 9, 82, 6, 114, 101, 97, 115, 111,
        110, 18, 20, 10, 5, 115, 116, 97, 114, 116, 24, 6, 32, 1, 40, 9, 82, 5, 115, 116, 97, 114,
        116, 18, 26, 10, 8, 100, 117, 114, 97, 116, 105, 111, 110, 24, 7, 32, 1, 40, 13, 82, 8,
        100, 117, 114, 97, 116, 105, 111, 110>>
    )
  end

  field :bans, 1, repeated: true, type: MumbleProto.BanList.BanEntry
  field :query, 2, optional: true, type: :bool, default: false
end

defmodule MumbleProto.TextMessage do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          actor: non_neg_integer,
          session: [non_neg_integer],
          channel_id: [non_neg_integer],
          tree_id: [non_neg_integer],
          message: String.t()
        }
  defstruct [:actor, :session, :channel_id, :tree_id, :message]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 11, 84, 101, 120, 116, 77, 101, 115, 115, 97, 103, 101, 18, 20, 10, 5, 97, 99, 116,
        111, 114, 24, 1, 32, 1, 40, 13, 82, 5, 97, 99, 116, 111, 114, 18, 24, 10, 7, 115, 101,
        115, 115, 105, 111, 110, 24, 2, 32, 3, 40, 13, 82, 7, 115, 101, 115, 115, 105, 111, 110,
        18, 29, 10, 10, 99, 104, 97, 110, 110, 101, 108, 95, 105, 100, 24, 3, 32, 3, 40, 13, 82,
        9, 99, 104, 97, 110, 110, 101, 108, 73, 100, 18, 23, 10, 7, 116, 114, 101, 101, 95, 105,
        100, 24, 4, 32, 3, 40, 13, 82, 6, 116, 114, 101, 101, 73, 100, 18, 24, 10, 7, 109, 101,
        115, 115, 97, 103, 101, 24, 5, 32, 2, 40, 9, 82, 7, 109, 101, 115, 115, 97, 103, 101>>
    )
  end

  field :actor, 1, optional: true, type: :uint32
  field :session, 2, repeated: true, type: :uint32
  field :channel_id, 3, repeated: true, type: :uint32
  field :tree_id, 4, repeated: true, type: :uint32
  field :message, 5, required: true, type: :string
end

defmodule MumbleProto.PermissionDenied do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          permission: non_neg_integer,
          channel_id: non_neg_integer,
          session: non_neg_integer,
          reason: String.t(),
          type: MumbleProto.PermissionDenied.DenyType.t(),
          name: String.t()
        }
  defstruct [:permission, :channel_id, :session, :reason, :type, :name]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 16, 80, 101, 114, 109, 105, 115, 115, 105, 111, 110, 68, 101, 110, 105, 101, 100, 18,
        30, 10, 10, 112, 101, 114, 109, 105, 115, 115, 105, 111, 110, 24, 1, 32, 1, 40, 13, 82,
        10, 112, 101, 114, 109, 105, 115, 115, 105, 111, 110, 18, 29, 10, 10, 99, 104, 97, 110,
        110, 101, 108, 95, 105, 100, 24, 2, 32, 1, 40, 13, 82, 9, 99, 104, 97, 110, 110, 101, 108,
        73, 100, 18, 24, 10, 7, 115, 101, 115, 115, 105, 111, 110, 24, 3, 32, 1, 40, 13, 82, 7,
        115, 101, 115, 115, 105, 111, 110, 18, 22, 10, 6, 114, 101, 97, 115, 111, 110, 24, 4, 32,
        1, 40, 9, 82, 6, 114, 101, 97, 115, 111, 110, 18, 58, 10, 4, 116, 121, 112, 101, 24, 5,
        32, 1, 40, 14, 50, 38, 46, 77, 117, 109, 98, 108, 101, 80, 114, 111, 116, 111, 46, 80,
        101, 114, 109, 105, 115, 115, 105, 111, 110, 68, 101, 110, 105, 101, 100, 46, 68, 101,
        110, 121, 84, 121, 112, 101, 82, 4, 116, 121, 112, 101, 18, 18, 10, 4, 110, 97, 109, 101,
        24, 6, 32, 1, 40, 9, 82, 4, 110, 97, 109, 101, 34, 133, 2, 10, 8, 68, 101, 110, 121, 84,
        121, 112, 101, 18, 8, 10, 4, 84, 101, 120, 116, 16, 0, 18, 14, 10, 10, 80, 101, 114, 109,
        105, 115, 115, 105, 111, 110, 16, 1, 18, 13, 10, 9, 83, 117, 112, 101, 114, 85, 115, 101,
        114, 16, 2, 18, 15, 10, 11, 67, 104, 97, 110, 110, 101, 108, 78, 97, 109, 101, 16, 3, 18,
        15, 10, 11, 84, 101, 120, 116, 84, 111, 111, 76, 111, 110, 103, 16, 4, 18, 7, 10, 3, 72,
        57, 75, 16, 5, 18, 20, 10, 16, 84, 101, 109, 112, 111, 114, 97, 114, 121, 67, 104, 97,
        110, 110, 101, 108, 16, 6, 18, 22, 10, 18, 77, 105, 115, 115, 105, 110, 103, 67, 101, 114,
        116, 105, 102, 105, 99, 97, 116, 101, 16, 7, 18, 12, 10, 8, 85, 115, 101, 114, 78, 97,
        109, 101, 16, 8, 18, 15, 10, 11, 67, 104, 97, 110, 110, 101, 108, 70, 117, 108, 108, 16,
        9, 18, 16, 10, 12, 78, 101, 115, 116, 105, 110, 103, 76, 105, 109, 105, 116, 16, 10, 18,
        21, 10, 17, 67, 104, 97, 110, 110, 101, 108, 67, 111, 117, 110, 116, 76, 105, 109, 105,
        116, 16, 11, 18, 24, 10, 20, 67, 104, 97, 110, 110, 101, 108, 76, 105, 115, 116, 101, 110,
        101, 114, 76, 105, 109, 105, 116, 16, 12, 18, 21, 10, 17, 85, 115, 101, 114, 76, 105, 115,
        116, 101, 110, 101, 114, 76, 105, 109, 105, 116, 16, 13>>
    )
  end

  field :permission, 1, optional: true, type: :uint32
  field :channel_id, 2, optional: true, type: :uint32
  field :session, 3, optional: true, type: :uint32
  field :reason, 4, optional: true, type: :string
  field :type, 5, optional: true, type: MumbleProto.PermissionDenied.DenyType, enum: true
  field :name, 6, optional: true, type: :string
end

defmodule MumbleProto.ACL.ChanGroup do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          name: String.t(),
          inherited: boolean,
          inherit: boolean,
          inheritable: boolean,
          add: [non_neg_integer],
          remove: [non_neg_integer],
          inherited_members: [non_neg_integer]
        }
  defstruct [:name, :inherited, :inherit, :inheritable, :add, :remove, :inherited_members]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 9, 67, 104, 97, 110, 71, 114, 111, 117, 112, 18, 18, 10, 4, 110, 97, 109, 101, 24, 1,
        32, 2, 40, 9, 82, 4, 110, 97, 109, 101, 18, 34, 10, 9, 105, 110, 104, 101, 114, 105, 116,
        101, 100, 24, 2, 32, 1, 40, 8, 58, 4, 116, 114, 117, 101, 82, 9, 105, 110, 104, 101, 114,
        105, 116, 101, 100, 18, 30, 10, 7, 105, 110, 104, 101, 114, 105, 116, 24, 3, 32, 1, 40, 8,
        58, 4, 116, 114, 117, 101, 82, 7, 105, 110, 104, 101, 114, 105, 116, 18, 38, 10, 11, 105,
        110, 104, 101, 114, 105, 116, 97, 98, 108, 101, 24, 4, 32, 1, 40, 8, 58, 4, 116, 114, 117,
        101, 82, 11, 105, 110, 104, 101, 114, 105, 116, 97, 98, 108, 101, 18, 16, 10, 3, 97, 100,
        100, 24, 5, 32, 3, 40, 13, 82, 3, 97, 100, 100, 18, 22, 10, 6, 114, 101, 109, 111, 118,
        101, 24, 6, 32, 3, 40, 13, 82, 6, 114, 101, 109, 111, 118, 101, 18, 43, 10, 17, 105, 110,
        104, 101, 114, 105, 116, 101, 100, 95, 109, 101, 109, 98, 101, 114, 115, 24, 7, 32, 3, 40,
        13, 82, 16, 105, 110, 104, 101, 114, 105, 116, 101, 100, 77, 101, 109, 98, 101, 114, 115>>
    )
  end

  field :name, 1, required: true, type: :string
  field :inherited, 2, optional: true, type: :bool, default: true
  field :inherit, 3, optional: true, type: :bool, default: true
  field :inheritable, 4, optional: true, type: :bool, default: true
  field :add, 5, repeated: true, type: :uint32
  field :remove, 6, repeated: true, type: :uint32
  field :inherited_members, 7, repeated: true, type: :uint32
end

defmodule MumbleProto.ACL.ChanACL do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          apply_here: boolean,
          apply_subs: boolean,
          inherited: boolean,
          user_id: non_neg_integer,
          group: String.t(),
          grant: non_neg_integer,
          deny: non_neg_integer
        }
  defstruct [:apply_here, :apply_subs, :inherited, :user_id, :group, :grant, :deny]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 7, 67, 104, 97, 110, 65, 67, 76, 18, 35, 10, 10, 97, 112, 112, 108, 121, 95, 104, 101,
        114, 101, 24, 1, 32, 1, 40, 8, 58, 4, 116, 114, 117, 101, 82, 9, 97, 112, 112, 108, 121,
        72, 101, 114, 101, 18, 35, 10, 10, 97, 112, 112, 108, 121, 95, 115, 117, 98, 115, 24, 2,
        32, 1, 40, 8, 58, 4, 116, 114, 117, 101, 82, 9, 97, 112, 112, 108, 121, 83, 117, 98, 115,
        18, 34, 10, 9, 105, 110, 104, 101, 114, 105, 116, 101, 100, 24, 3, 32, 1, 40, 8, 58, 4,
        116, 114, 117, 101, 82, 9, 105, 110, 104, 101, 114, 105, 116, 101, 100, 18, 23, 10, 7,
        117, 115, 101, 114, 95, 105, 100, 24, 4, 32, 1, 40, 13, 82, 6, 117, 115, 101, 114, 73,
        100, 18, 20, 10, 5, 103, 114, 111, 117, 112, 24, 5, 32, 1, 40, 9, 82, 5, 103, 114, 111,
        117, 112, 18, 20, 10, 5, 103, 114, 97, 110, 116, 24, 6, 32, 1, 40, 13, 82, 5, 103, 114,
        97, 110, 116, 18, 18, 10, 4, 100, 101, 110, 121, 24, 7, 32, 1, 40, 13, 82, 4, 100, 101,
        110, 121>>
    )
  end

  field :apply_here, 1, optional: true, type: :bool, default: true
  field :apply_subs, 2, optional: true, type: :bool, default: true
  field :inherited, 3, optional: true, type: :bool, default: true
  field :user_id, 4, optional: true, type: :uint32
  field :group, 5, optional: true, type: :string
  field :grant, 6, optional: true, type: :uint32
  field :deny, 7, optional: true, type: :uint32
end

defmodule MumbleProto.ACL do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          channel_id: non_neg_integer,
          inherit_acls: boolean,
          groups: [MumbleProto.ACL.ChanGroup.t()],
          acls: [MumbleProto.ACL.ChanACL.t()],
          query: boolean
        }
  defstruct [:channel_id, :inherit_acls, :groups, :acls, :query]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 3, 65, 67, 76, 18, 29, 10, 10, 99, 104, 97, 110, 110, 101, 108, 95, 105, 100, 24, 1,
        32, 2, 40, 13, 82, 9, 99, 104, 97, 110, 110, 101, 108, 73, 100, 18, 39, 10, 12, 105, 110,
        104, 101, 114, 105, 116, 95, 97, 99, 108, 115, 24, 2, 32, 1, 40, 8, 58, 4, 116, 114, 117,
        101, 82, 11, 105, 110, 104, 101, 114, 105, 116, 65, 99, 108, 115, 18, 50, 10, 6, 103, 114,
        111, 117, 112, 115, 24, 3, 32, 3, 40, 11, 50, 26, 46, 77, 117, 109, 98, 108, 101, 80, 114,
        111, 116, 111, 46, 65, 67, 76, 46, 67, 104, 97, 110, 71, 114, 111, 117, 112, 82, 6, 103,
        114, 111, 117, 112, 115, 18, 44, 10, 4, 97, 99, 108, 115, 24, 4, 32, 3, 40, 11, 50, 24,
        46, 77, 117, 109, 98, 108, 101, 80, 114, 111, 116, 111, 46, 65, 67, 76, 46, 67, 104, 97,
        110, 65, 67, 76, 82, 4, 97, 99, 108, 115, 18, 27, 10, 5, 113, 117, 101, 114, 121, 24, 5,
        32, 1, 40, 8, 58, 5, 102, 97, 108, 115, 101, 82, 5, 113, 117, 101, 114, 121, 26, 226, 1,
        10, 9, 67, 104, 97, 110, 71, 114, 111, 117, 112, 18, 18, 10, 4, 110, 97, 109, 101, 24, 1,
        32, 2, 40, 9, 82, 4, 110, 97, 109, 101, 18, 34, 10, 9, 105, 110, 104, 101, 114, 105, 116,
        101, 100, 24, 2, 32, 1, 40, 8, 58, 4, 116, 114, 117, 101, 82, 9, 105, 110, 104, 101, 114,
        105, 116, 101, 100, 18, 30, 10, 7, 105, 110, 104, 101, 114, 105, 116, 24, 3, 32, 1, 40, 8,
        58, 4, 116, 114, 117, 101, 82, 7, 105, 110, 104, 101, 114, 105, 116, 18, 38, 10, 11, 105,
        110, 104, 101, 114, 105, 116, 97, 98, 108, 101, 24, 4, 32, 1, 40, 8, 58, 4, 116, 114, 117,
        101, 82, 11, 105, 110, 104, 101, 114, 105, 116, 97, 98, 108, 101, 18, 16, 10, 3, 97, 100,
        100, 24, 5, 32, 3, 40, 13, 82, 3, 97, 100, 100, 18, 22, 10, 6, 114, 101, 109, 111, 118,
        101, 24, 6, 32, 3, 40, 13, 82, 6, 114, 101, 109, 111, 118, 101, 18, 43, 10, 17, 105, 110,
        104, 101, 114, 105, 116, 101, 100, 95, 109, 101, 109, 98, 101, 114, 115, 24, 7, 32, 3, 40,
        13, 82, 16, 105, 110, 104, 101, 114, 105, 116, 101, 100, 77, 101, 109, 98, 101, 114, 115,
        26, 208, 1, 10, 7, 67, 104, 97, 110, 65, 67, 76, 18, 35, 10, 10, 97, 112, 112, 108, 121,
        95, 104, 101, 114, 101, 24, 1, 32, 1, 40, 8, 58, 4, 116, 114, 117, 101, 82, 9, 97, 112,
        112, 108, 121, 72, 101, 114, 101, 18, 35, 10, 10, 97, 112, 112, 108, 121, 95, 115, 117,
        98, 115, 24, 2, 32, 1, 40, 8, 58, 4, 116, 114, 117, 101, 82, 9, 97, 112, 112, 108, 121,
        83, 117, 98, 115, 18, 34, 10, 9, 105, 110, 104, 101, 114, 105, 116, 101, 100, 24, 3, 32,
        1, 40, 8, 58, 4, 116, 114, 117, 101, 82, 9, 105, 110, 104, 101, 114, 105, 116, 101, 100,
        18, 23, 10, 7, 117, 115, 101, 114, 95, 105, 100, 24, 4, 32, 1, 40, 13, 82, 6, 117, 115,
        101, 114, 73, 100, 18, 20, 10, 5, 103, 114, 111, 117, 112, 24, 5, 32, 1, 40, 9, 82, 5,
        103, 114, 111, 117, 112, 18, 20, 10, 5, 103, 114, 97, 110, 116, 24, 6, 32, 1, 40, 13, 82,
        5, 103, 114, 97, 110, 116, 18, 18, 10, 4, 100, 101, 110, 121, 24, 7, 32, 1, 40, 13, 82, 4,
        100, 101, 110, 121>>
    )
  end

  field :channel_id, 1, required: true, type: :uint32
  field :inherit_acls, 2, optional: true, type: :bool, default: true
  field :groups, 3, repeated: true, type: MumbleProto.ACL.ChanGroup
  field :acls, 4, repeated: true, type: MumbleProto.ACL.ChanACL
  field :query, 5, optional: true, type: :bool, default: false
end

defmodule MumbleProto.QueryUsers do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          ids: [non_neg_integer],
          names: [String.t()]
        }
  defstruct [:ids, :names]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 10, 81, 117, 101, 114, 121, 85, 115, 101, 114, 115, 18, 16, 10, 3, 105, 100, 115, 24,
        1, 32, 3, 40, 13, 82, 3, 105, 100, 115, 18, 20, 10, 5, 110, 97, 109, 101, 115, 24, 2, 32,
        3, 40, 9, 82, 5, 110, 97, 109, 101, 115>>
    )
  end

  field :ids, 1, repeated: true, type: :uint32
  field :names, 2, repeated: true, type: :string
end

defmodule MumbleProto.CryptSetup do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          key: binary,
          client_nonce: binary,
          server_nonce: binary
        }
  defstruct [:key, :client_nonce, :server_nonce]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 10, 67, 114, 121, 112, 116, 83, 101, 116, 117, 112, 18, 16, 10, 3, 107, 101, 121, 24,
        1, 32, 1, 40, 12, 82, 3, 107, 101, 121, 18, 33, 10, 12, 99, 108, 105, 101, 110, 116, 95,
        110, 111, 110, 99, 101, 24, 2, 32, 1, 40, 12, 82, 11, 99, 108, 105, 101, 110, 116, 78,
        111, 110, 99, 101, 18, 33, 10, 12, 115, 101, 114, 118, 101, 114, 95, 110, 111, 110, 99,
        101, 24, 3, 32, 1, 40, 12, 82, 11, 115, 101, 114, 118, 101, 114, 78, 111, 110, 99, 101>>
    )
  end

  field :key, 1, optional: true, type: :bytes
  field :client_nonce, 2, optional: true, type: :bytes
  field :server_nonce, 3, optional: true, type: :bytes
end

defmodule MumbleProto.ContextActionModify do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          action: String.t(),
          text: String.t(),
          context: non_neg_integer,
          operation: MumbleProto.ContextActionModify.Operation.t()
        }
  defstruct [:action, :text, :context, :operation]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 19, 67, 111, 110, 116, 101, 120, 116, 65, 99, 116, 105, 111, 110, 77, 111, 100, 105,
        102, 121, 18, 22, 10, 6, 97, 99, 116, 105, 111, 110, 24, 1, 32, 2, 40, 9, 82, 6, 97, 99,
        116, 105, 111, 110, 18, 18, 10, 4, 116, 101, 120, 116, 24, 2, 32, 1, 40, 9, 82, 4, 116,
        101, 120, 116, 18, 24, 10, 7, 99, 111, 110, 116, 101, 120, 116, 24, 3, 32, 1, 40, 13, 82,
        7, 99, 111, 110, 116, 101, 120, 116, 18, 72, 10, 9, 111, 112, 101, 114, 97, 116, 105, 111,
        110, 24, 4, 32, 1, 40, 14, 50, 42, 46, 77, 117, 109, 98, 108, 101, 80, 114, 111, 116, 111,
        46, 67, 111, 110, 116, 101, 120, 116, 65, 99, 116, 105, 111, 110, 77, 111, 100, 105, 102,
        121, 46, 79, 112, 101, 114, 97, 116, 105, 111, 110, 82, 9, 111, 112, 101, 114, 97, 116,
        105, 111, 110, 34, 44, 10, 7, 67, 111, 110, 116, 101, 120, 116, 18, 10, 10, 6, 83, 101,
        114, 118, 101, 114, 16, 1, 18, 11, 10, 7, 67, 104, 97, 110, 110, 101, 108, 16, 2, 18, 8,
        10, 4, 85, 115, 101, 114, 16, 4, 34, 32, 10, 9, 79, 112, 101, 114, 97, 116, 105, 111, 110,
        18, 7, 10, 3, 65, 100, 100, 16, 0, 18, 10, 10, 6, 82, 101, 109, 111, 118, 101, 16, 1>>
    )
  end

  field :action, 1, required: true, type: :string
  field :text, 2, optional: true, type: :string
  field :context, 3, optional: true, type: :uint32
  field :operation, 4, optional: true, type: MumbleProto.ContextActionModify.Operation, enum: true
end

defmodule MumbleProto.ContextAction do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          session: non_neg_integer,
          channel_id: non_neg_integer,
          action: String.t()
        }
  defstruct [:session, :channel_id, :action]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 13, 67, 111, 110, 116, 101, 120, 116, 65, 99, 116, 105, 111, 110, 18, 24, 10, 7, 115,
        101, 115, 115, 105, 111, 110, 24, 1, 32, 1, 40, 13, 82, 7, 115, 101, 115, 115, 105, 111,
        110, 18, 29, 10, 10, 99, 104, 97, 110, 110, 101, 108, 95, 105, 100, 24, 2, 32, 1, 40, 13,
        82, 9, 99, 104, 97, 110, 110, 101, 108, 73, 100, 18, 22, 10, 6, 97, 99, 116, 105, 111,
        110, 24, 3, 32, 2, 40, 9, 82, 6, 97, 99, 116, 105, 111, 110>>
    )
  end

  field :session, 1, optional: true, type: :uint32
  field :channel_id, 2, optional: true, type: :uint32
  field :action, 3, required: true, type: :string
end

defmodule MumbleProto.UserList.User do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          user_id: non_neg_integer,
          name: String.t(),
          last_seen: String.t(),
          last_channel: non_neg_integer
        }
  defstruct [:user_id, :name, :last_seen, :last_channel]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 4, 85, 115, 101, 114, 18, 23, 10, 7, 117, 115, 101, 114, 95, 105, 100, 24, 1, 32, 2,
        40, 13, 82, 6, 117, 115, 101, 114, 73, 100, 18, 18, 10, 4, 110, 97, 109, 101, 24, 2, 32,
        1, 40, 9, 82, 4, 110, 97, 109, 101, 18, 27, 10, 9, 108, 97, 115, 116, 95, 115, 101, 101,
        110, 24, 3, 32, 1, 40, 9, 82, 8, 108, 97, 115, 116, 83, 101, 101, 110, 18, 33, 10, 12,
        108, 97, 115, 116, 95, 99, 104, 97, 110, 110, 101, 108, 24, 4, 32, 1, 40, 13, 82, 11, 108,
        97, 115, 116, 67, 104, 97, 110, 110, 101, 108>>
    )
  end

  field :user_id, 1, required: true, type: :uint32
  field :name, 2, optional: true, type: :string
  field :last_seen, 3, optional: true, type: :string
  field :last_channel, 4, optional: true, type: :uint32
end

defmodule MumbleProto.UserList do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          users: [MumbleProto.UserList.User.t()]
        }
  defstruct [:users]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 8, 85, 115, 101, 114, 76, 105, 115, 116, 18, 48, 10, 5, 117, 115, 101, 114, 115, 24,
        1, 32, 3, 40, 11, 50, 26, 46, 77, 117, 109, 98, 108, 101, 80, 114, 111, 116, 111, 46, 85,
        115, 101, 114, 76, 105, 115, 116, 46, 85, 115, 101, 114, 82, 5, 117, 115, 101, 114, 115,
        26, 115, 10, 4, 85, 115, 101, 114, 18, 23, 10, 7, 117, 115, 101, 114, 95, 105, 100, 24, 1,
        32, 2, 40, 13, 82, 6, 117, 115, 101, 114, 73, 100, 18, 18, 10, 4, 110, 97, 109, 101, 24,
        2, 32, 1, 40, 9, 82, 4, 110, 97, 109, 101, 18, 27, 10, 9, 108, 97, 115, 116, 95, 115, 101,
        101, 110, 24, 3, 32, 1, 40, 9, 82, 8, 108, 97, 115, 116, 83, 101, 101, 110, 18, 33, 10,
        12, 108, 97, 115, 116, 95, 99, 104, 97, 110, 110, 101, 108, 24, 4, 32, 1, 40, 13, 82, 11,
        108, 97, 115, 116, 67, 104, 97, 110, 110, 101, 108>>
    )
  end

  field :users, 1, repeated: true, type: MumbleProto.UserList.User
end

defmodule MumbleProto.VoiceTarget.Target do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          session: [non_neg_integer],
          channel_id: non_neg_integer,
          group: String.t(),
          links: boolean,
          children: boolean
        }
  defstruct [:session, :channel_id, :group, :links, :children]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 6, 84, 97, 114, 103, 101, 116, 18, 24, 10, 7, 115, 101, 115, 115, 105, 111, 110, 24,
        1, 32, 3, 40, 13, 82, 7, 115, 101, 115, 115, 105, 111, 110, 18, 29, 10, 10, 99, 104, 97,
        110, 110, 101, 108, 95, 105, 100, 24, 2, 32, 1, 40, 13, 82, 9, 99, 104, 97, 110, 110, 101,
        108, 73, 100, 18, 20, 10, 5, 103, 114, 111, 117, 112, 24, 3, 32, 1, 40, 9, 82, 5, 103,
        114, 111, 117, 112, 18, 27, 10, 5, 108, 105, 110, 107, 115, 24, 4, 32, 1, 40, 8, 58, 5,
        102, 97, 108, 115, 101, 82, 5, 108, 105, 110, 107, 115, 18, 33, 10, 8, 99, 104, 105, 108,
        100, 114, 101, 110, 24, 5, 32, 1, 40, 8, 58, 5, 102, 97, 108, 115, 101, 82, 8, 99, 104,
        105, 108, 100, 114, 101, 110>>
    )
  end

  field :session, 1, repeated: true, type: :uint32
  field :channel_id, 2, optional: true, type: :uint32
  field :group, 3, optional: true, type: :string
  field :links, 4, optional: true, type: :bool, default: false
  field :children, 5, optional: true, type: :bool, default: false
end

defmodule MumbleProto.VoiceTarget do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          id: non_neg_integer,
          targets: [MumbleProto.VoiceTarget.Target.t()]
        }
  defstruct [:id, :targets]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 11, 86, 111, 105, 99, 101, 84, 97, 114, 103, 101, 116, 18, 14, 10, 2, 105, 100, 24, 1,
        32, 1, 40, 13, 82, 2, 105, 100, 18, 57, 10, 7, 116, 97, 114, 103, 101, 116, 115, 24, 2,
        32, 3, 40, 11, 50, 31, 46, 77, 117, 109, 98, 108, 101, 80, 114, 111, 116, 111, 46, 86,
        111, 105, 99, 101, 84, 97, 114, 103, 101, 116, 46, 84, 97, 114, 103, 101, 116, 82, 7, 116,
        97, 114, 103, 101, 116, 115, 26, 151, 1, 10, 6, 84, 97, 114, 103, 101, 116, 18, 24, 10, 7,
        115, 101, 115, 115, 105, 111, 110, 24, 1, 32, 3, 40, 13, 82, 7, 115, 101, 115, 115, 105,
        111, 110, 18, 29, 10, 10, 99, 104, 97, 110, 110, 101, 108, 95, 105, 100, 24, 2, 32, 1, 40,
        13, 82, 9, 99, 104, 97, 110, 110, 101, 108, 73, 100, 18, 20, 10, 5, 103, 114, 111, 117,
        112, 24, 3, 32, 1, 40, 9, 82, 5, 103, 114, 111, 117, 112, 18, 27, 10, 5, 108, 105, 110,
        107, 115, 24, 4, 32, 1, 40, 8, 58, 5, 102, 97, 108, 115, 101, 82, 5, 108, 105, 110, 107,
        115, 18, 33, 10, 8, 99, 104, 105, 108, 100, 114, 101, 110, 24, 5, 32, 1, 40, 8, 58, 5,
        102, 97, 108, 115, 101, 82, 8, 99, 104, 105, 108, 100, 114, 101, 110>>
    )
  end

  field :id, 1, optional: true, type: :uint32
  field :targets, 2, repeated: true, type: MumbleProto.VoiceTarget.Target
end

defmodule MumbleProto.PermissionQuery do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          channel_id: non_neg_integer,
          permissions: non_neg_integer,
          flush: boolean
        }
  defstruct [:channel_id, :permissions, :flush]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 15, 80, 101, 114, 109, 105, 115, 115, 105, 111, 110, 81, 117, 101, 114, 121, 18, 29,
        10, 10, 99, 104, 97, 110, 110, 101, 108, 95, 105, 100, 24, 1, 32, 1, 40, 13, 82, 9, 99,
        104, 97, 110, 110, 101, 108, 73, 100, 18, 32, 10, 11, 112, 101, 114, 109, 105, 115, 115,
        105, 111, 110, 115, 24, 2, 32, 1, 40, 13, 82, 11, 112, 101, 114, 109, 105, 115, 115, 105,
        111, 110, 115, 18, 27, 10, 5, 102, 108, 117, 115, 104, 24, 3, 32, 1, 40, 8, 58, 5, 102,
        97, 108, 115, 101, 82, 5, 102, 108, 117, 115, 104>>
    )
  end

  field :channel_id, 1, optional: true, type: :uint32
  field :permissions, 2, optional: true, type: :uint32
  field :flush, 3, optional: true, type: :bool, default: false
end

defmodule MumbleProto.CodecVersion do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          alpha: integer,
          beta: integer,
          prefer_alpha: boolean,
          opus: boolean
        }
  defstruct [:alpha, :beta, :prefer_alpha, :opus]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 12, 67, 111, 100, 101, 99, 86, 101, 114, 115, 105, 111, 110, 18, 20, 10, 5, 97, 108,
        112, 104, 97, 24, 1, 32, 2, 40, 5, 82, 5, 97, 108, 112, 104, 97, 18, 18, 10, 4, 98, 101,
        116, 97, 24, 2, 32, 2, 40, 5, 82, 4, 98, 101, 116, 97, 18, 39, 10, 12, 112, 114, 101, 102,
        101, 114, 95, 97, 108, 112, 104, 97, 24, 3, 32, 2, 40, 8, 58, 4, 116, 114, 117, 101, 82,
        11, 112, 114, 101, 102, 101, 114, 65, 108, 112, 104, 97, 18, 25, 10, 4, 111, 112, 117,
        115, 24, 4, 32, 1, 40, 8, 58, 5, 102, 97, 108, 115, 101, 82, 4, 111, 112, 117, 115>>
    )
  end

  field :alpha, 1, required: true, type: :int32
  field :beta, 2, required: true, type: :int32
  field :prefer_alpha, 3, required: true, type: :bool, default: true
  field :opus, 4, optional: true, type: :bool, default: false
end

defmodule MumbleProto.UserStats.Stats do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          good: non_neg_integer,
          late: non_neg_integer,
          lost: non_neg_integer,
          resync: non_neg_integer
        }
  defstruct [:good, :late, :lost, :resync]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 5, 83, 116, 97, 116, 115, 18, 18, 10, 4, 103, 111, 111, 100, 24, 1, 32, 1, 40, 13, 82,
        4, 103, 111, 111, 100, 18, 18, 10, 4, 108, 97, 116, 101, 24, 2, 32, 1, 40, 13, 82, 4, 108,
        97, 116, 101, 18, 18, 10, 4, 108, 111, 115, 116, 24, 3, 32, 1, 40, 13, 82, 4, 108, 111,
        115, 116, 18, 22, 10, 6, 114, 101, 115, 121, 110, 99, 24, 4, 32, 1, 40, 13, 82, 6, 114,
        101, 115, 121, 110, 99>>
    )
  end

  field :good, 1, optional: true, type: :uint32
  field :late, 2, optional: true, type: :uint32
  field :lost, 3, optional: true, type: :uint32
  field :resync, 4, optional: true, type: :uint32
end

defmodule MumbleProto.UserStats do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          session: non_neg_integer,
          stats_only: boolean,
          certificates: [binary],
          from_client: MumbleProto.UserStats.Stats.t() | nil,
          from_server: MumbleProto.UserStats.Stats.t() | nil,
          udp_packets: non_neg_integer,
          tcp_packets: non_neg_integer,
          udp_ping_avg: float | :infinity | :negative_infinity | :nan,
          udp_ping_var: float | :infinity | :negative_infinity | :nan,
          tcp_ping_avg: float | :infinity | :negative_infinity | :nan,
          tcp_ping_var: float | :infinity | :negative_infinity | :nan,
          version: MumbleProto.Version.t() | nil,
          celt_versions: [integer],
          address: binary,
          bandwidth: non_neg_integer,
          onlinesecs: non_neg_integer,
          idlesecs: non_neg_integer,
          strong_certificate: boolean,
          opus: boolean
        }
  defstruct [
    :session,
    :stats_only,
    :certificates,
    :from_client,
    :from_server,
    :udp_packets,
    :tcp_packets,
    :udp_ping_avg,
    :udp_ping_var,
    :tcp_ping_avg,
    :tcp_ping_var,
    :version,
    :celt_versions,
    :address,
    :bandwidth,
    :onlinesecs,
    :idlesecs,
    :strong_certificate,
    :opus
  ]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 9, 85, 115, 101, 114, 83, 116, 97, 116, 115, 18, 24, 10, 7, 115, 101, 115, 115, 105,
        111, 110, 24, 1, 32, 1, 40, 13, 82, 7, 115, 101, 115, 115, 105, 111, 110, 18, 36, 10, 10,
        115, 116, 97, 116, 115, 95, 111, 110, 108, 121, 24, 2, 32, 1, 40, 8, 58, 5, 102, 97, 108,
        115, 101, 82, 9, 115, 116, 97, 116, 115, 79, 110, 108, 121, 18, 34, 10, 12, 99, 101, 114,
        116, 105, 102, 105, 99, 97, 116, 101, 115, 24, 3, 32, 3, 40, 12, 82, 12, 99, 101, 114,
        116, 105, 102, 105, 99, 97, 116, 101, 115, 18, 61, 10, 11, 102, 114, 111, 109, 95, 99,
        108, 105, 101, 110, 116, 24, 4, 32, 1, 40, 11, 50, 28, 46, 77, 117, 109, 98, 108, 101, 80,
        114, 111, 116, 111, 46, 85, 115, 101, 114, 83, 116, 97, 116, 115, 46, 83, 116, 97, 116,
        115, 82, 10, 102, 114, 111, 109, 67, 108, 105, 101, 110, 116, 18, 61, 10, 11, 102, 114,
        111, 109, 95, 115, 101, 114, 118, 101, 114, 24, 5, 32, 1, 40, 11, 50, 28, 46, 77, 117,
        109, 98, 108, 101, 80, 114, 111, 116, 111, 46, 85, 115, 101, 114, 83, 116, 97, 116, 115,
        46, 83, 116, 97, 116, 115, 82, 10, 102, 114, 111, 109, 83, 101, 114, 118, 101, 114, 18,
        31, 10, 11, 117, 100, 112, 95, 112, 97, 99, 107, 101, 116, 115, 24, 6, 32, 1, 40, 13, 82,
        10, 117, 100, 112, 80, 97, 99, 107, 101, 116, 115, 18, 31, 10, 11, 116, 99, 112, 95, 112,
        97, 99, 107, 101, 116, 115, 24, 7, 32, 1, 40, 13, 82, 10, 116, 99, 112, 80, 97, 99, 107,
        101, 116, 115, 18, 32, 10, 12, 117, 100, 112, 95, 112, 105, 110, 103, 95, 97, 118, 103,
        24, 8, 32, 1, 40, 2, 82, 10, 117, 100, 112, 80, 105, 110, 103, 65, 118, 103, 18, 32, 10,
        12, 117, 100, 112, 95, 112, 105, 110, 103, 95, 118, 97, 114, 24, 9, 32, 1, 40, 2, 82, 10,
        117, 100, 112, 80, 105, 110, 103, 86, 97, 114, 18, 32, 10, 12, 116, 99, 112, 95, 112, 105,
        110, 103, 95, 97, 118, 103, 24, 10, 32, 1, 40, 2, 82, 10, 116, 99, 112, 80, 105, 110, 103,
        65, 118, 103, 18, 32, 10, 12, 116, 99, 112, 95, 112, 105, 110, 103, 95, 118, 97, 114, 24,
        11, 32, 1, 40, 2, 82, 10, 116, 99, 112, 80, 105, 110, 103, 86, 97, 114, 18, 46, 10, 7,
        118, 101, 114, 115, 105, 111, 110, 24, 12, 32, 1, 40, 11, 50, 20, 46, 77, 117, 109, 98,
        108, 101, 80, 114, 111, 116, 111, 46, 86, 101, 114, 115, 105, 111, 110, 82, 7, 118, 101,
        114, 115, 105, 111, 110, 18, 35, 10, 13, 99, 101, 108, 116, 95, 118, 101, 114, 115, 105,
        111, 110, 115, 24, 13, 32, 3, 40, 5, 82, 12, 99, 101, 108, 116, 86, 101, 114, 115, 105,
        111, 110, 115, 18, 24, 10, 7, 97, 100, 100, 114, 101, 115, 115, 24, 14, 32, 1, 40, 12, 82,
        7, 97, 100, 100, 114, 101, 115, 115, 18, 28, 10, 9, 98, 97, 110, 100, 119, 105, 100, 116,
        104, 24, 15, 32, 1, 40, 13, 82, 9, 98, 97, 110, 100, 119, 105, 100, 116, 104, 18, 30, 10,
        10, 111, 110, 108, 105, 110, 101, 115, 101, 99, 115, 24, 16, 32, 1, 40, 13, 82, 10, 111,
        110, 108, 105, 110, 101, 115, 101, 99, 115, 18, 26, 10, 8, 105, 100, 108, 101, 115, 101,
        99, 115, 24, 17, 32, 1, 40, 13, 82, 8, 105, 100, 108, 101, 115, 101, 99, 115, 18, 52, 10,
        18, 115, 116, 114, 111, 110, 103, 95, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101,
        24, 18, 32, 1, 40, 8, 58, 5, 102, 97, 108, 115, 101, 82, 17, 115, 116, 114, 111, 110, 103,
        67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 18, 25, 10, 4, 111, 112, 117, 115, 24,
        19, 32, 1, 40, 8, 58, 5, 102, 97, 108, 115, 101, 82, 4, 111, 112, 117, 115, 26, 91, 10, 5,
        83, 116, 97, 116, 115, 18, 18, 10, 4, 103, 111, 111, 100, 24, 1, 32, 1, 40, 13, 82, 4,
        103, 111, 111, 100, 18, 18, 10, 4, 108, 97, 116, 101, 24, 2, 32, 1, 40, 13, 82, 4, 108,
        97, 116, 101, 18, 18, 10, 4, 108, 111, 115, 116, 24, 3, 32, 1, 40, 13, 82, 4, 108, 111,
        115, 116, 18, 22, 10, 6, 114, 101, 115, 121, 110, 99, 24, 4, 32, 1, 40, 13, 82, 6, 114,
        101, 115, 121, 110, 99>>
    )
  end

  field :session, 1, optional: true, type: :uint32
  field :stats_only, 2, optional: true, type: :bool, default: false
  field :certificates, 3, repeated: true, type: :bytes
  field :from_client, 4, optional: true, type: MumbleProto.UserStats.Stats
  field :from_server, 5, optional: true, type: MumbleProto.UserStats.Stats
  field :udp_packets, 6, optional: true, type: :uint32
  field :tcp_packets, 7, optional: true, type: :uint32
  field :udp_ping_avg, 8, optional: true, type: :float
  field :udp_ping_var, 9, optional: true, type: :float
  field :tcp_ping_avg, 10, optional: true, type: :float
  field :tcp_ping_var, 11, optional: true, type: :float
  field :version, 12, optional: true, type: MumbleProto.Version
  field :celt_versions, 13, repeated: true, type: :int32
  field :address, 14, optional: true, type: :bytes
  field :bandwidth, 15, optional: true, type: :uint32
  field :onlinesecs, 16, optional: true, type: :uint32
  field :idlesecs, 17, optional: true, type: :uint32
  field :strong_certificate, 18, optional: true, type: :bool, default: false
  field :opus, 19, optional: true, type: :bool, default: false
end

defmodule MumbleProto.RequestBlob do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          session_texture: [non_neg_integer],
          session_comment: [non_neg_integer],
          channel_description: [non_neg_integer]
        }
  defstruct [:session_texture, :session_comment, :channel_description]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 11, 82, 101, 113, 117, 101, 115, 116, 66, 108, 111, 98, 18, 39, 10, 15, 115, 101, 115,
        115, 105, 111, 110, 95, 116, 101, 120, 116, 117, 114, 101, 24, 1, 32, 3, 40, 13, 82, 14,
        115, 101, 115, 115, 105, 111, 110, 84, 101, 120, 116, 117, 114, 101, 18, 39, 10, 15, 115,
        101, 115, 115, 105, 111, 110, 95, 99, 111, 109, 109, 101, 110, 116, 24, 2, 32, 3, 40, 13,
        82, 14, 115, 101, 115, 115, 105, 111, 110, 67, 111, 109, 109, 101, 110, 116, 18, 47, 10,
        19, 99, 104, 97, 110, 110, 101, 108, 95, 100, 101, 115, 99, 114, 105, 112, 116, 105, 111,
        110, 24, 3, 32, 3, 40, 13, 82, 18, 99, 104, 97, 110, 110, 101, 108, 68, 101, 115, 99, 114,
        105, 112, 116, 105, 111, 110>>
    )
  end

  field :session_texture, 1, repeated: true, type: :uint32
  field :session_comment, 2, repeated: true, type: :uint32
  field :channel_description, 3, repeated: true, type: :uint32
end

defmodule MumbleProto.ServerConfig do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          max_bandwidth: non_neg_integer,
          welcome_text: String.t(),
          allow_html: boolean,
          message_length: non_neg_integer,
          image_message_length: non_neg_integer,
          max_users: non_neg_integer
        }
  defstruct [
    :max_bandwidth,
    :welcome_text,
    :allow_html,
    :message_length,
    :image_message_length,
    :max_users
  ]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 12, 83, 101, 114, 118, 101, 114, 67, 111, 110, 102, 105, 103, 18, 35, 10, 13, 109, 97,
        120, 95, 98, 97, 110, 100, 119, 105, 100, 116, 104, 24, 1, 32, 1, 40, 13, 82, 12, 109, 97,
        120, 66, 97, 110, 100, 119, 105, 100, 116, 104, 18, 33, 10, 12, 119, 101, 108, 99, 111,
        109, 101, 95, 116, 101, 120, 116, 24, 2, 32, 1, 40, 9, 82, 11, 119, 101, 108, 99, 111,
        109, 101, 84, 101, 120, 116, 18, 29, 10, 10, 97, 108, 108, 111, 119, 95, 104, 116, 109,
        108, 24, 3, 32, 1, 40, 8, 82, 9, 97, 108, 108, 111, 119, 72, 116, 109, 108, 18, 37, 10,
        14, 109, 101, 115, 115, 97, 103, 101, 95, 108, 101, 110, 103, 116, 104, 24, 4, 32, 1, 40,
        13, 82, 13, 109, 101, 115, 115, 97, 103, 101, 76, 101, 110, 103, 116, 104, 18, 48, 10, 20,
        105, 109, 97, 103, 101, 95, 109, 101, 115, 115, 97, 103, 101, 95, 108, 101, 110, 103, 116,
        104, 24, 5, 32, 1, 40, 13, 82, 18, 105, 109, 97, 103, 101, 77, 101, 115, 115, 97, 103,
        101, 76, 101, 110, 103, 116, 104, 18, 27, 10, 9, 109, 97, 120, 95, 117, 115, 101, 114,
        115, 24, 6, 32, 1, 40, 13, 82, 8, 109, 97, 120, 85, 115, 101, 114, 115>>
    )
  end

  field :max_bandwidth, 1, optional: true, type: :uint32
  field :welcome_text, 2, optional: true, type: :string
  field :allow_html, 3, optional: true, type: :bool
  field :message_length, 4, optional: true, type: :uint32
  field :image_message_length, 5, optional: true, type: :uint32
  field :max_users, 6, optional: true, type: :uint32
end

defmodule MumbleProto.SuggestConfig do
  @moduledoc false
  use Protobuf, syntax: :proto2

  @type t :: %__MODULE__{
          version: non_neg_integer,
          positional: boolean,
          push_to_talk: boolean
        }
  defstruct [:version, :positional, :push_to_talk]

  def descriptor do
    # credo:disable-for-next-line
    Elixir.Google.Protobuf.DescriptorProto.decode(
      <<10, 13, 83, 117, 103, 103, 101, 115, 116, 67, 111, 110, 102, 105, 103, 18, 24, 10, 7, 118,
        101, 114, 115, 105, 111, 110, 24, 1, 32, 1, 40, 13, 82, 7, 118, 101, 114, 115, 105, 111,
        110, 18, 30, 10, 10, 112, 111, 115, 105, 116, 105, 111, 110, 97, 108, 24, 2, 32, 1, 40, 8,
        82, 10, 112, 111, 115, 105, 116, 105, 111, 110, 97, 108, 18, 32, 10, 12, 112, 117, 115,
        104, 95, 116, 111, 95, 116, 97, 108, 107, 24, 3, 32, 1, 40, 8, 82, 10, 112, 117, 115, 104,
        84, 111, 84, 97, 108, 107>>
    )
  end

  field :version, 1, optional: true, type: :uint32
  field :positional, 2, optional: true, type: :bool
  field :push_to_talk, 3, optional: true, type: :bool
end
