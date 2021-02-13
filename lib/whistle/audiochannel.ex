defmodule Whistle.AudioChannel do
  @type packet_type :: :celt_alpha | :ping | :speex | :celt_beta | :opus | integer
  @type packet_target :: :normal_talking  | :server_loopback | integer

  defstruct [:type, :target, :payload]

  @type_to_int %{
    celt_alpha: 0,
    ping: 1,
    speex: 2,
    celt_beta: 3,
    opus: 4,
  }

  @int_to_type %{
    0 => :celt_alpha,
    1 => :ping,
    2 => :speex,
    3 => :celt_beta,
    4 => :opus,
  }

  @target_to_int %{
    normal_talking: 0,
    server_loopback: 31
  }

  @int_to_target %{
    0 => :normal_talking,
    31 => :server_loopback
  }

  def decode(packet, _opts \\ []) do
    <<type::3, target::5, payload::binary>> = packet
    type_enum = Map.get(@int_to_type, type, type)
    %__MODULE__{
      type: type_enum,
      target: Map.get(@int_to_target, target, target),
      payload: case type_enum do
        :opus ->
          Whistle.AudioData.decode(payload)
        _ ->
          payload
      end
    }
  end

  def encode(%__MODULE__{type: type, target: target, payload: payload}, _opts \\ []) do
    type_int = Map.get(@type_to_int, type, type)
    target_int = Map.get(@target_to_int, target, target)
    <<type_int::3, target_int::5, payload::binary>>
  end
end
