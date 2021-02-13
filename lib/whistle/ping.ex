defmodule Whistle.Ping do
  @moduledoc """
  Pings a Mumble server over UDP and returns information.
  """

  defstruct [:version, :connected_users, :max_users, :allowed_bandwidth]

  def ping(server, port \\ 64738, timeout \\ 1000) do
    {:ok, socket} = :gen_udp.open(port, [:binary, {:active, false}])
    session_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
    try do
      :gen_udp.send(socket, server, port, <<0, 0, 0, 0>> <> session_id)
      {:ok, {_addr, _port, reply_raw}} = :gen_udp.recv(socket, 0, timeout)
      # not actually a protobuf!
      <<_::8, v_maj::8, v_min::8, v_patch::8, _ident::64, connected_users::32, max_users::32, allowed_bandwidth::32>> = reply_raw
      {:ok, version} = "#{to_string(v_maj)}.#{to_string(v_min)}.#{to_string(v_patch)}"
                       |> Version.parse
      %__MODULE__{
        version: version,
        connected_users: connected_users,
        max_users: max_users,
        allowed_bandwidth: allowed_bandwidth
      }
    after
      :gen_udp.close(socket)
    end
  end
end
