defmodule Whistle.OpusDec do
  @ogg_magic "OggS"
  @ogg_header_size 27

  @opus_magic "OpusHead"
  @opus_comment_magic "OpusTags"

  defp parse_ogg_header(<<@ogg_magic, 0::8, type::8, granule::64-little, serial::32-little, sequence::32-little, checksum::32-little, page_segments::8>>) do
    %{
      type: type,
      granule: granule,
      serial: serial,
      sequence: sequence,
      checksum: checksum,
      page_segments: page_segments
    }
  end

  defp parse_opus_header(<<@opus_magic, 1::8, channels::8, preskip::16-little, sample::32-little, gain::16-little, mapping_family::8, channel_mapping::binary>>) do
    # RFC 7845 section 5.1 item 6
    real_gain = :math.pow(10, gain/(20.0*256))
    # XXX: Parse channel mapping
    %{
      channels: channels,
      preskip: preskip,
      sample: sample,
      gain: real_gain,
    }
  end

  defp mark_if_partial(header, segment_table, segments) do
    atom = if List.last(segment_table) == 255 do :partial else :complete end
    {atom, header, segment_table, segments}
  end

  defp parse_stream(stream, last_page, decoded) do
    case IO.binread(stream, @ogg_header_size) do
      :eof ->
        decoded
      header_bin ->
        header = parse_ogg_header(header_bin)
        # segment table is an array of bytes, corresponding to lengths
        # read each sequentially, (XXX?) then combine if last entry
        # in the previous segment table was 255 (continuation)
        segment_table = IO.binread(stream, header.page_segments)
                        |> :binary.bin_to_list
        segments = segment_table
                   |> Enum.map(fn x -> IO.binread(stream, x) end)
                   |> Enum.join
        # remember, decoded means complete
        {new_last_page, new_decoded} = case last_page do
          nil ->
            # first page (always a single page)
            opus_header = {:opus_header, parse_opus_header(segments)}
            {opus_header, decoded ++ [opus_header]}
          {:opus_header, _} ->
            # second page (a comment, but can be multiple pages)
            # XXX: probably will break down with multiple pages?
            comment = {:comment}
            {comment, decoded ++ [comment]}
          {:partial, _last_header, last_segment_table, last_segments} ->
            case mark_if_partial(header, last_segment_table ++ segment_table, last_segments <> segments) do
              {:partial, _, _, _} = partial ->
                {partial, decoded}
              {:complete, _, _, _} = complete ->
                {complete, decoded ++ [complete]}
            end
          _ ->
            case mark_if_partial(header, segment_table, segments) do
              {:partial, _, _, _} = partial ->
                {partial, decoded}
              {:complete, _, _, _} = complete ->
                {complete, decoded ++ [complete]}
            end
        end
        parse_stream(stream, new_last_page, new_decoded)
    end
  end

  def parse_stream(stream) do
    parse_stream(stream, nil, [])
  end

  def parse_file(file_name) do
    {:ok, file} = File.open(file_name, [:read, :binary])
    try do
      parse_stream(file)
    after
      File.close(file)
    end
  end

  # XXX: Temporary
  def firehose(list, session,  count \\ 0) do
    case list do
      [] ->
        :ok
      [{:complete, _, _,  <<_type::5, _stereo::1, 0::2, frame::binary>>} | tail] ->
        GenServer.cast(session, {:opus_frame, count, frame})
        firehose(tail, session, count + 1)
      [{:comment} | tail] -> 
        firehose(tail, session, count)
      [{:opus_header, _} | tail] -> 
        firehose(tail, session, count)
    end
  end
end
