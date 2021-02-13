defmodule Whistle.AudioData do
  require Bitwise
  # Opus only. The frames for incoming (decode) and outging (encode) are different.
  
  defstruct [:session, :sequence, :last, :opus_data]

  def decode(packet, _opts \\ []) do
    # The header has already been decoded
    # XXX: ugly as sin
    {sid, rest1} = Whistle.Varint.decode(packet)
    {seq, rest2} = Whistle.Varint.decode(rest1)
    {opus_len, rest3} = Whistle.Varint.decode(rest2)
    real_len = Bitwise.&&&(opus_len, 0x1FFF)
    last_one = Bitwise.&&&(opus_len, 0x2000) > 0
    #IO.puts("Binary size is #{byte_size(rest3)} but the declared size is #{real_len}")
    #IO.puts(byte_size(rest3) >= real_len)
    # XXX: elixir pattern matching has problem with ::size(var)?
    opus_data = :binary.part(rest3, 0, real_len)
    # we don't care about the three floats at the end
    %__MODULE__{
      session: sid,
      sequence: seq,
      last: last_one,
      opus_data: opus_data
    }
  end

  def encode(%__MODULE__{sequence: sequence, opus_data: opus_data}, _opts \\ []) do
    seq_bin = Whistle.Varint.encode(sequence)
    opus_len_bin = Whistle.Varint.encode(byte_size(opus_data))
    pos_bin = <<0::float-size(32), 0::float-size(32), 0::float-size(32)>>
    seq_bin <> opus_len_bin <> pos_bin
  end
end
