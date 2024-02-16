defmodule Explorer.EthRpcHelper do
  alias Explorer.Chain.Hash.Address

  def address_hash_validator(address_hash) do
    case Address.cast(address_hash) do
      {:ok, _} -> :ok
      :error -> {:error, "invalid address"}
    end
  end

  def block_validator(block_tag) when block_tag in ["latest", "earliest", "pending"], do: :ok

  def block_validator("0x" <> block_number) do
    case Integer.parse(block_number, 16) do
      {_integer, ""} -> :ok
      _ -> {:error, "invalid block number"}
    end
  end

  def block_validator(_), do: {:error, "invalid block number"}
end
