defmodule Explorer.EthRpcHelper do
  alias Explorer.Chain.{Data, Hash.Address}

  @invalid_address "Invalid address"
  @invalid_block_number "Invalid block number"
  @invalid_integer "Invalid integer"
  @missed_to_address "Missed `to` address"
  @invalid_bool "Invalid bool"

  def address_hash_validator(address_hash, message \\ @invalid_address) do
    case Address.cast(address_hash) do
      {:ok, _} -> :ok
      :error -> {:error, message}
    end
  end

  def block_validator(block_tag) when block_tag in ["latest", "earliest", "pending"], do: :ok

  def block_validator(block_number) do
    parse_integer(block_number) || {:error, @invalid_block_number}
  end

  def integer_validator(hex) do
    parse_integer(hex) || {:error, @invalid_integer}
  end

  def eth_call_validator(%{"to" => to_address} = eth_call) do
    with :ok <- address_hash_validator(to_address, "Invalid `to` address"),
         :ok <- validate_optional_address(eth_call["from"], "from"),
         :ok <- validate_optional_integer(eth_call["gas"], "gas"),
         :ok <- validate_optional_integer(eth_call["gasPrice"], "gasPrice"),
         :ok <- validate_optional_integer(eth_call["value"], "value"),
         :ok <- validate_optional_hex_data(eth_call["input"], "input") do
      :ok
    else
      error ->
        error
    end
  end

  def eth_call_validator(_), do: {:error, @missed_to_address}

  def bool_validator(bool) when is_boolean(bool), do: :ok
  def bool_validator(_), do: {:error, @invalid_bool}

  defp validate_optional_address(nil, _), do: :ok

  defp validate_optional_address(address_hash, field_name) do
    address_hash_validator(address_hash, "Invalid `#{field_name}` address")
  end

  defp validate_optional_integer(nil, _), do: :ok

  defp validate_optional_integer(integer, field_name) do
    parse_integer(integer) || {:error, "Invalid `#{field_name}` quantity"}
  end

  defp parse_integer("0x"), do: :ok

  defp parse_integer("0x" <> hex_integer) do
    case Integer.parse(hex_integer, 16) do
      {_integer, ""} -> :ok
      _ -> nil
    end
  end

  defp parse_integer(_), do: nil

  defp validate_optional_hex_data(nil, _), do: :ok

  defp validate_optional_hex_data(data, field_name) do
    case Data.cast(data) do
      {:ok, _} -> :ok
      _ -> {:error, "Invalid `#{field_name}` data"}
    end
  end
end
