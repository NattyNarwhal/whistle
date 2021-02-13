defmodule Whistle.Varint do
  # https://mumble-protocol.readthedocs.io/en/latest/voice_data.html?highlight=tunnel#variable-length-integer-encoding
  require Bitwise

  def decode(<<0::1, int::7-big, rest::binary>>) do
    {int, rest}
  end

  def decode(<<0b10::2, int::14-big, rest::binary>>) do
    {int, rest}
  end

  def decode(<<0b110::3, int::21-big, rest::binary>>) do
    {int, rest}
  end

  def decode(<<0b1110::4, int::28-big, rest::binary>>) do
    {int, rest}
  end

  def decode(<<0b111100::6, _::2, int::32-big, rest::binary>>) do
    {int, rest}
  end

  def decode(<<0b111101::6, _::2, int::64-big, rest::binary>>) do
    {int, rest}
  end

  def decode(<<0b111110::6, _::2, varint::binary>>) do
    # Negative recursive
    -(decode(varint))
  end
  
  def decode(<<0b111111::6, int::2, rest::binary>>) do
    # 2-bit byte-inverted negative
    {Bitwise.~~~(int), rest}
  end

  def encode(int) do
    #IO.inspect(int, label: "Encoding")
    # XXX: this could prob be a pattern match on encode()
    cond do
      (int < 0 && int > -16) ->
        <<0b111111::6, Bitwise-(int)::2>>
      (int >= 0 && int <= 0x7F) ->
        <<0::1, int::7-big>>
      (int > 0x7F && int <= 0x3FFF) ->
        <<0b10::2, int::14-big>>
      (int > 0x3FFF && int <= 0x1FFFFF) ->
        <<0b110::3, int::21-big>>
      (int > 0x1FFFFF && int <= 0xFFFFFFF) ->
        <<0b1110::4, int::28-big>>
      (int > 0xFFFFFFF && int <= 0xFFFFFFFF) ->
        <<0b111100::6, 0::2, int::32-big>>
      (int > 0xFFFFFFFF && int <= 0xFFFFFFFFFFFFFFFF) ->
        <<0b111100::6, 0::2, int::32-big>>
      int < 0 ->
        <<0b111110::6, 0::2, encode(-(int))::binary>>
    end
  end
end
