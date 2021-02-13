defmodule Whistle.Session do
  use GenServer

  @impl true
  def init(opts \\ %{}) do
    server = Map.get(opts, :server)
    port = Map.get(opts, :port, 64738)
    username = Map.get(opts, :username)
    password = Map.get(opts, :password)
    timeout = Map.get(opts, :timeout, 1000)
    socket = open(server, port, timeout)
    state = %{
      server: server,
      port: port,
      username: username,
      password: password,
      timeout: timeout,
      socket: socket
    }
    # The server doesn't have to send it first, so we'll send the first shot
    # (uMurmur doesn't, Murmur does)
    send_version(socket)
    send_authenticate(socket, state)
    send_ping(socket)
    {:ok, state}
  end

  defp open(server, port, timeout) do
    {:ok, socket} = :ssl.connect(server, port, [mode: :binary], timeout)

    socket
  end

  defp send_ping(socket) do
    # XXX: Get statistics on our connection
    ping = MumbleProto.Ping.new(%{timestamp: :os.system_time()})
    encoded_ping = Whistle.Prefix.encode(ping)

    :ssl.send(socket, encoded_ping)
  end

  defp send_version(socket) do
    my_version = Whistle.Prefix.encode(%MumbleProto.Version{
      version: 0x00010302,
      release: "Whistle",
      os: "Elixir",
      os_version: System.version()
    })

    :ssl.send(socket, my_version)
    #IO.puts("sent version")
  end

  defp send_authenticate(socket, state) do
    my_auth = Whistle.Prefix.encode(%MumbleProto.Authenticate{
      username: Map.get(state, :username),
      password: Map.get(state, :password, ""),
      tokens: [],
      celt_versions: [],
      opus: true
    })

    :ssl.send(socket, my_auth)
    #IO.puts("sent auth")
  end

  @impl true
  def handle_info({:ssl, _, packet}, state) do
    # probably TOO aggressive
    send_ping(state.socket)
    #IO.inspect(packet, [limit: :infinity, label: "Raw Reply"])
    decoded = Whistle.Prefix.decode(packet)
    if decoded != nil && decoded.__struct__ not in [MumbleProto.Ping, MumbleProto.TextMessage, MumbleProto.UDPTunnel] do IO.inspect(decoded, label: "Decoded Reply") else nil end
    case decoded do
      %MumbleProto.Version{} ->
        {:noreply, state}
      %MumbleProto.Reject{type: type, reason: reason} ->
        {:stop, {:murmur_reject, type, reason}, state}
      %MumbleProto.CryptSetup{client_nonce: client_nonce, key: key, server_nonce: server_nonce} ->
        new_state = state
                    |> Map.put(:client_nonce, client_nonce)
                    |> Map.put(:key, key)
                    |> Map.put(:server_nonce, server_nonce)
        {:noreply, new_state}
      %MumbleProto.TextMessage{message: message} ->
        IO.puts("Someone said " <> message)
        {:noreply, state}
      %MumbleProto.UDPTunnel{packet: packet_ac} ->
        decoded_ac = Whistle.AudioChannel.decode(packet_ac)
        {:noreply, state}
      _ ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:ssl_closed, _socket}, state) do
    {:stop, :ssl_closed, state}
  end

  @impl true
  def handle_cast({:opus_frame, sequence, opus_frame}, state) do
    audio_data = %Whistle.AudioData{sequence: sequence, opus_data: opus_frame}
                 |> IO.inspect(label: "Audio Data Out")
                 |> Whistle.AudioData.encode
    audio_channel = %Whistle.AudioChannel{type: :opus, target: :normal_talking, payload: audio_data}
                    |> IO.inspect(label: "Audio Channel Out")
                    |> Whistle.AudioChannel.encode
    udp_tunnel = MumbleProto.UDPTunnel.new(%{packet: audio_channel})
                 |> Whistle.Prefix.encode
    :ssl.send(state.socket, udp_tunnel)
    {:noreply, state}
  end

  @impl true
  def handle_cast(req, state) do
    {:noreply, state}
  end

  @impl true
  def handle_call(req, from, state) do
    {:ok, state}
  end
end
