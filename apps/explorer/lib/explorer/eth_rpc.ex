defmodule Explorer.EthRPC do
  @moduledoc """
  Ethereum JSON RPC methods logic implementation.
  """

  import Explorer.EthRpcHelper

  alias Ecto.Type, as: EctoType
  alias Explorer.{Chain, Helper, Repo}
  alias Explorer.Chain.{Block, Data, Hash, Hash.Address, Wei}
  alias Explorer.Chain.Cache.{BlockNumber, GasPriceOracle}
  alias Explorer.Etherscan.{Blocks, Logs, RPC}

  @methods %{
    "eth_blockNumber" => %{
      action: :eth_block_number,
      notes: nil,
      example: """
      {"id": 0, "jsonrpc": "2.0", "method": "eth_blockNumber", "params": []}
      """,
      params: [],
      result: """
      {"id": 0, "jsonrpc": "2.0", "result": "0xb3415c"}
      """
    },
    "eth_getBalance" => %{
      action: :eth_get_balance,
      notes: """
      The `earliest` parameter will not work as expected currently, because genesis block balances
      are not currently imported
      """,
      example: """
      {"id": 0, "jsonrpc": "2.0", "method": "eth_getBalance", "params": ["0x0000000000000000000000000000000000000007", "latest"]}
      """,
      params: [
        %{
          name: "Data",
          description: "20 Bytes - address to check for balance",
          type: "string",
          default: nil,
          required: true
        },
        %{
          name: "Quantity|Tag",
          description: "Integer block number, or the string \"latest\", \"earliest\" or \"pending\"",
          type: "string",
          default: "latest",
          required: true
        }
      ],
      result: """
      {"id": 0, "jsonrpc": "2.0", "result": "0x0234c8a3397aab58"}
      """
    },
    "eth_getLogs" => %{
      action: :eth_get_logs,
      notes: """
      Will never return more than 1000 log entries.\n
      For this reason, you can use pagination options to request the next page. Pagination options params: {"logIndex": "3D", "blockNumber": "6423AC"} which include parameters from the last log received from the previous request. These three parameters are required for pagination.
      """,
      example: """
      {"id": 0, "jsonrpc": "2.0", "method": "eth_getLogs",
       "params": [
        {"address": "0xc78Be425090Dbd437532594D12267C5934Cc6c6f",
         "paging_options": {"logIndex": "3D", "blockNumber": "6423AC"},
         "fromBlock": "earliest",
         "toBlock": "latest",
         "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}
      """,
      params: [
        %{name: "Object", description: "The filter options", type: "json", default: nil, required: true}
      ],
      result: """
      {
        "id":0,
        "jsonrpc":"2.0",
        "result": [{
          "logIndex": "0x1",
          "blockNumber":"0x1b4",
          "blockHash": "0x8216c5785ac562ff41e2dcfdf5785ac562ff41e2dcfdf829c5a142f1fccd7d",
          "transactionHash":  "0xdf829c5a142f1fccd7d8216c5785ac562ff41e2dcfdf5785ac562ff41e2dcf",
          "transactionIndex": "0x0",
          "address": "0x16c5785ac562ff41e2dcfdf829c5a142f1fccd7d",
          "data":"0x0000000000000000000000000000000000000000000000000000000000000000",
          "topics": ["0x59ebeb90bc63057b6515673c3ecf9438e5058bca0f92585014eced636878c9a5"]
          }]
      }
      """
    },
    "eth_gasPrice" => %{
      action: :eth_gas_price,
      notes: """
      Returns the average gas price per gas in wei.
      """,
      example: """
      {"jsonrpc": "2.0", "id": 4, "method": "eth_gasPrice", "params": []}
      """,
      params: [],
      result: """
      {"jsonrpc": "2.0", "id": 4, "result": "0xbf69c09bb"}
      """
    },
    "eth_getTransactionByHash" => %{
      action: :eth_get_transaction_by_hash,
      notes: """
      """,
      example: """
      {"jsonrpc": "2.0", "id": 4, "method": "eth_getTransactionByHash", "params": ["0x98318a5a22e363928d4565382c1022a8aed169b6a657f639c2f5c6e2c5114e4c"]}
      """,
      params: [
        %{
          name: "Data",
          description: "32 Bytes - transaction hash to get",
          type: "string",
          default: nil,
          required: true
        }
      ],
      result: """
      {"jsonrpc": "2.0", "id": 4, "result": "0xbf69c09bb"}
      """
    }
  }

  @proxy_methods %{
    "eth_getTransactionCount" => %{
      arity: 2,
      params_validators: [&address_hash_validator/1, &block_validator/1],
      example: """
      {"id": 0, "jsonrpc": "2.0", "method": "eth_getTransactionCount", "params": ["0x0000000000000000000000000000000000000007", "latest"]}
      """,
      result: """
      {"id": 0, "jsonrpc": "2.0", "result": "0x2"}
      """
    },
    "eth_getCode" => %{
      arity: 2,
      params_validators: [&address_hash_validator/1, &block_validator/1],
      example: """
      {"jsonrpc":"2.0","id": 0,"method":"eth_getCode","params":["0x1BF313AADe1e1f76295943f40B558Eb13Db7aA99", "latest"]}
      """,
      result: """
      {
        "jsonrpc": "2.0",
        "result": "0x60806040523661001357610011610017565b005b6100115b610027610022610067565b61009f565b565b606061004e838360405180606001604052806027815260200161026b602791396100c3565b9392505050565b6001600160a01b03163b151590565b90565b600061009a7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc546001600160a01b031690565b905090565b3660008037600080366000845af43d6000803e8080156100be573d6000f35b3d6000fd5b6060600080856001600160a01b0316856040516100e0919061021b565b600060405180830381855af49150503d806000811461011b576040519150601f19603f3d011682016040523d82523d6000602084013e610120565b606091505b50915091506101318683838761013b565b9695505050505050565b606083156101af5782516000036101a8576001600160a01b0385163b6101a85760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e747261637400000060448201526064015b60405180910390fd5b50816101b9565b6101b983836101c1565b949350505050565b8151156101d15781518083602001fd5b8060405162461bcd60e51b815260040161019f9190610237565b60005b838110156102065781810151838201526020016101ee565b83811115610215576000848401525b50505050565b6000825161022d8184602087016101eb565b9190910192915050565b60208152600082518060208401526102568160408501602087016101eb565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564a2646970667358221220ef6e0977d993c1b69ec75a2f9fd6a53122d4ad4f9d71477641195afb6a6a45dd64736f6c634300080f0033",
        "id": 0
      }
      """
    },
    "eth_getStorageAt" => %{
      arity: 3,
      params_validators: [&address_hash_validator/1, &integer_validator/1, &block_validator/1],
      example: """
      {"jsonrpc":"2.0","id":4,"method":"eth_getStorageAt","params":["0x1643E812aE58766192Cf7D2Cf9567dF2C37e9B7F", "0x", "latest"]}
      """,
      result: """
      {
        "jsonrpc": "2.0",
        "result": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "id": 4
      }
      """
    },
    "eth_estimateGas" => %{
      arity: 2,
      params_validators: [&eth_call_validator/1, &block_validator/1],
      example: """
      {"jsonrpc":"2.0","id": 0,"method":"eth_estimateGas","params":[{"to": "0x1643E812aE58766192Cf7D2Cf9567dF2C37e9B7F", "input": "0xd4aae0c4", "from": "0x1643E812aE58766192Cf7D2Cf9567dF2C37e9B7F"}, "latest"]}
      """,
      result: """
      {
        "jsonrpc": "2.0",
        "result": "0x5bb6",
        "id": 0
      }
      """
    },
    "eth_getBlockByNumber" => %{
      arity: 2,
      params_validators: [&block_validator/1, &bool_validator/1],
      example: """
      {"jsonrpc":"2.0","id": 0,"method":"eth_getBlockByNumber","params":["latest", false]}
      """,
      result: """
      {
        "baseFeePerGas": "0x8",
        "blobGasUsed": "0xa0000",
        "difficulty": "0x0",
        "excessBlobGas": "0x4b80000",
        "extraData": "0xd883010d09846765746888676f312e32312e36856c696e7578",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x13d180",
        "hash": "0x84851ee1a5b1382898138ad9647088636e7f0dd8007d12571106dbb18bb2a6d3",
        "logsBloom": "0x8208004000200008000004004101000000000020004003000100004200000000000030000400000008000028400002000001000000028100c00000001060208000114080080000001008000b002008000001004001420080000000000000000002040000021800000054000100004810100000040028010008004a100208001248c2400010048000800000010000003000002480020002000000000000098010020000001a000200500001402004000081028681800001000400020500000000c0140022040200000002200100000000006000000000008000010244000020000110202804200018008104000000000008000000001002000400000000004000",
        "miner": "0x94750381be1aba0504c666ee1db118f68f0780d4",
        "mixHash": "0x39de028cc3fb8d9baf91b0720a0d2cdca8a343266e62e6a9dfc01554fa4fb3cf",
        "nonce": "0x0000000000000000",
        "number": "0xa0f41e",
        "parentBeaconBlockRoot": "0x374099b35fe33790ce4f9743115aac2bbfb2f797be7808a98a1030e67effbfad",
        "parentHash": "0x030cbe8bba962ac1f052e509afa5013dfa3c7ca584354435e21ad6ecfeddddd6",
        "receiptsRoot": "0x4c42cd59b1a73381a496b408c1287a87d0fb11f61099090cadc70b6bd2328795",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "size": "0x1cbb",
        "stateRoot": "0x88ddfb5cf8102a1ee92758d0020d3e7bce6d28e9e40932157687a8131b6fa928",
        "timestamp": "0x65cfb770",
        "totalDifficulty": "0xa4a470",
        "transactions": [
            "0x3bf013bfafc3f14ceb5e4ae782d3b0ad16dfbaf7a7c05061c3411908ea50628a",
            "0xb44bd74266efc598852f3344a750e520d0620c3c6061eb2f910bab5e412d5824",
            "0x78532bbd27a4bccbe33e9b4eb675a9b731935e9aa108062ae628e87aac353f26",
            "0xd002f4ff977ebaf38923ceef4f4cf03c13bfc08265f719e2669236cdca757321",
            "0x34ead4a41f04d809468e5c9d245c2a90a93d316ebde0e7bd289572d42b119b94",
            "0xbc4777663752a2d40d4c778352d7655a2254d438d09c3de10ff037d38c47cb6a",
            "0x582dadac41286a8c1de49df6058643cc5e23c41389ccfde93c9e1a579d4dc4b3",
            "0x347f8272088c288ffb24afff4aa7a0386ab9c5b8813e0ef82fcc5f58e79bb3ef",
            "0xd0503d439cc41a2521292d67a1b20afe01d368f4f15ef7700066388267cbd83a",
            "0x75f3f0aeede8d9f93ee6022834a856627eeb0f3a3e0a1739bf191472cd666b8d",
            "0x08ae89549a14431b03d2dbdeb1955b5a0bdd152169cc519949a460813bb4acba",
            "0xb0f238b083759e76176452c8d880c0ce84d867957f30f82d0b3ef66581ba5c2f",
            "0x15743c890560823e6e5539ceb12380833a2721a0a2a04a0e2435b88890496e6e",
            "0x42e23e92fe82e6af75af1dfe4c4869aa87011386c455165cd81725b90537e451",
            "0x5176583adbb4f881c8627c12dfe9723ecdf496b07da919eddaa2b009a8983cfd",
            "0x3e2afe2ea46dfc1467eca7cf8e08ca5c9ea21a6d8c382fff8299189357328040",
            "0x93993c91f54642f81379ae5fe7983025bd12219254de98f6ead5f701f759810e"
        ],
        "transactionsRoot": "0x7b40ab6aa1d0bef1c878fb175b949315e8e8edf59eba9a9a1e3ddabe321827ae",
        "uncles": [],
        "withdrawals": [
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2b19e9",
                "index": "0x1cd40c4",
                "validatorIndex": "0x9387a"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2b0ad0",
                "index": "0x1cd40c5",
                "validatorIndex": "0x9387b"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2b89a3",
                "index": "0x1cd40c6",
                "validatorIndex": "0x9387c"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x29dcbc",
                "index": "0x1cd40c7",
                "validatorIndex": "0x9387d"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2a1e54",
                "index": "0x1cd40c8",
                "validatorIndex": "0x9387e"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2a3dc3",
                "index": "0x1cd40c9",
                "validatorIndex": "0x9387f"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2ad9f6",
                "index": "0x1cd40ca",
                "validatorIndex": "0x93880"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2abc0d",
                "index": "0x1cd40cb",
                "validatorIndex": "0x93881"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2b1ede",
                "index": "0x1cd40cc",
                "validatorIndex": "0x93882"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2b09b9",
                "index": "0x1cd40cd",
                "validatorIndex": "0x93883"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2ad1b1",
                "index": "0x1cd40ce",
                "validatorIndex": "0x93884"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2ae98a",
                "index": "0x1cd40cf",
                "validatorIndex": "0x93885"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2b85ff",
                "index": "0x1cd40d0",
                "validatorIndex": "0x93886"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2b4ed6",
                "index": "0x1cd40d1",
                "validatorIndex": "0x93887"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x29192d",
                "index": "0x1cd40d2",
                "validatorIndex": "0x93888"
            },
            {
                "address": "0xdc62f9e8c34be08501cdef4ebde0a280f576d762",
                "amount": "0x2adcad",
                "index": "0x1cd40d3",
                "validatorIndex": "0x93889"
            }
        ],
        "withdrawalsRoot": "0x978f98003a89e0db5adfac08f7631fccf9dc984a25260b483848ff0197927bea"
      }
      """
    }
  }

  @index_to_word %{
    0 => "first",
    1 => "second",
    2 => "third",
    3 => "fourth"
  }

  @incorrect_number_of_params "Incorrect number of params."

  # https://www.jsonrpc.org/specification
  def responses(requests) do
    requests =
      requests
      |> Enum.with_index()

    proxy_requests =
      requests
      |> Enum.reduce(%{}, fn {request, index}, acc ->
        case proxy_method?(request) do
          true ->
            Map.put(acc, index, request)

          {:error, _reason} = error ->
            Map.put(acc, index, error)

          false ->
            acc
        end
      end)
      |> json_rpc()

    Enum.map(requests, fn {request, index} ->
      with {:proxy, nil} <- {:proxy, proxy_requests[index]},
           {:id, {:ok, id}} <- {:id, Map.fetch(request, "id")},
           {:request, {:ok, result}} <- {:request, do_eth_request(request)} do
        format_success(result, id)
      else
        {:id, :error} -> format_error("id is a required field", 0)
        {:request, {:error, message}} -> format_error(message, Map.get(request, "id"))
        {:proxy, {:error, message}} -> format_error(message, Map.get(request, "id"))
        {:proxy, %{result: result}} -> format_success(result, Map.get(request, "id"))
        {:proxy, %{error: error}} -> format_error(error, Map.get(request, "id"))
      end
    end)
  end

  defp proxy_method?(%{"jsonrpc" => "2.0", "method" => method, "params" => params, "id" => id})
       when is_list(params) and (is_number(id) or is_binary(id) or is_nil(id)) do
    with method_definition when not is_nil(method_definition) <- @proxy_methods[method],
         {:arity, true} <- {:arity, method_definition[:arity] == length(params)},
         :ok <- validate_params(method_definition[:params_validators], params) do
      true
    else
      {:error, _reason} = error ->
        error

      {:arity, false} ->
        {:error, @incorrect_number_of_params}

      _ ->
        false
    end
  end

  defp proxy_method?(_), do: false

  defp validate_params(validators, params) do
    validators
    |> Enum.zip(params)
    |> Enum.reduce_while(:ok, fn
      {validator_func, param}, :ok ->
        {:cont, validator_func.(param)}

      _, error ->
        {:halt, error}
    end)
  end

  defp json_rpc(map) when is_map(map) do
    to_request =
      Enum.flat_map(Map.values(map), fn
        {:error, _} ->
          []

        map when is_map(map) ->
          [request_to_elixir(map)]
      end)

    with [_ | _] = to_request <- to_request,
         {:ok, responses} <-
           EthereumJSONRPC.json_rpc(to_request, Application.get_env(:explorer, :json_rpc_named_arguments)) do
      {map, []} =
        Enum.map_reduce(map, responses, fn
          {_index, {:error, _}} = elem, responses ->
            {elem, responses}

          {index, _request}, [response | other_responses] ->
            {{index, response}, other_responses}
        end)

      Enum.into(map, %{})
    else
      [] ->
        map

      {:error, _reason} = error ->
        {results, []} =
          Enum.map(map, fn
            {_index, {:error, _}} = elem ->
              elem

            {index, _request} ->
              {index, error}
          end)

        Enum.into(results, %{})
    end
  end

  defp request_to_elixir(%{"jsonrpc" => json_rpc, "method" => method, "params" => params, "id" => id}) do
    %{jsonrpc: json_rpc, method: method, params: params, id: id}
  end

  def eth_block_number do
    max_block_number = BlockNumber.get_max()

    max_block_number_hex =
      max_block_number
      |> encode_quantity()

    {:ok, max_block_number_hex}
  end

  def eth_get_balance(address_param, block_param \\ nil) do
    with {:address, {:ok, address}} <- {:address, Chain.string_to_address_hash(address_param)},
         {:block, {:ok, block}} <- {:block, block_param(block_param)},
         {:balance, {:ok, balance}} <- {:balance, Blocks.get_balance_as_of_block(address, block)} do
      {:ok, Wei.hex_format(balance)}
    else
      {:address, :error} ->
        {:error, "Query parameter 'address' is invalid"}

      {:block, :error} ->
        {:error, "Query parameter 'block' is invalid"}

      {:balance, {:error, :not_found}} ->
        {:error, "Balance not found"}
    end
  end

  def eth_gas_price do
    case GasPriceOracle.get_gas_prices() do
      {:ok, gas_prices} ->
        {:ok, Wei.hex_format(gas_prices[:average][:wei])}

      _ ->
        {:error, "Gas price is not estimated yet"}
    end
  end

  def eth_get_transaction_by_hash(transaction_hash_string) do
    with {:transaction_hash, {:ok, transaction_hash}} <-
           {:transaction_hash, Chain.string_to_transaction_hash(transaction_hash_string)},
         {:transaction, {:ok, transaction}} <- {:transaction, Chain.hash_to_transaction(transaction_hash, [])} do
      render_transaction(transaction)
    else
      {:transaction_hash, :error} ->
        {:error, "Transaction hash is invalid"}

      {:transaction, _} ->
        {:ok, nil}
    end
  end

  defp render_transaction(transaction) do
    {:ok,
     %{
       "blockHash" => transaction.block_hash,
       "blockNumber" => encode_quantity(transaction.block_number),
       "from" => transaction.from_address_hash,
       "gas" => encode_quantity(transaction.gas),
       "gasPrice" => transaction.gas_price |> Wei.to(:wei) |> encode_quantity(),
       "maxPriorityFeePerGas" => transaction.max_priority_fee_per_gas |> Wei.to(:wei) |> encode_quantity(),
       "maxFeePerGas" => transaction.max_fee_per_gas |> Wei.to(:wei) |> encode_quantity(),
       "hash" => transaction.hash,
       "input" => transaction.input,
       "nonce" => encode_quantity(transaction.nonce),
       "to" => transaction.to_address_hash,
       "transactionIndex" => encode_quantity(transaction.index),
       "value" => transaction.value |> Wei.to(:wei) |> encode_quantity(),
       "type" => encode_quantity(transaction.type),
       "chainId" => :block_scout_web |> Application.get_env(:chain_id) |> Helper.parse_integer() |> encode_quantity(),
       "v" => encode_quantity(transaction.v),
       "r" => encode_quantity(transaction.r),
       "s" => encode_quantity(transaction.s)
     }}
  end

  def eth_get_logs(filter_options) do
    with {:ok, address_or_topic_params} <- address_or_topic_params(filter_options),
         {:ok, from_block_param, to_block_param} <- logs_blocks_filter(filter_options),
         {:ok, from_block} <- cast_block(from_block_param),
         {:ok, to_block} <- cast_block(to_block_param),
         {:ok, paging_options} <- paging_options(filter_options) do
      filter =
        address_or_topic_params
        |> Map.put(:from_block, from_block)
        |> Map.put(:to_block, to_block)
        |> Map.put(:allow_non_consensus, true)

      logs =
        filter
        |> Logs.list_logs(paging_options)
        |> Enum.map(&render_log/1)

      {:ok, logs}
    else
      {:error, message} when is_bitstring(message) ->
        {:error, message}

      {:error, :empty} ->
        {:ok, []}

      _ ->
        {:error, "Something went wrong."}
    end
  end

  defp render_log(log) do
    topics =
      Enum.reject(
        [log.first_topic, log.second_topic, log.third_topic, log.fourth_topic],
        &is_nil/1
      )

    %{
      "address" => to_string(log.address_hash),
      "blockHash" => to_string(log.block_hash),
      "blockNumber" => Integer.to_string(log.block_number, 16),
      "data" => to_string(log.data),
      "logIndex" => Integer.to_string(log.index, 16),
      "removed" => log.block_consensus == false,
      "topics" => topics,
      "transactionHash" => to_string(log.transaction_hash),
      "transactionIndex" => log.transaction_index,
      "transactionLogIndex" => log.index
    }
  end

  defp cast_block("0x" <> hexadecimal_digits = input) do
    case Integer.parse(hexadecimal_digits, 16) do
      {integer, ""} -> {:ok, integer}
      _ -> {:error, input <> " is not a valid block number"}
    end
  end

  defp cast_block(integer) when is_integer(integer), do: {:ok, integer}
  defp cast_block(_), do: {:error, "invalid block number"}

  defp address_or_topic_params(filter_options) do
    address_param = Map.get(filter_options, "address")
    topics_param = Map.get(filter_options, "topics")

    with {:ok, address} <- validate_address(address_param),
         {:ok, topics} <- validate_topics(topics_param) do
      address_and_topics(address, topics)
    end
  end

  defp address_and_topics(nil, nil), do: {:error, "Must supply one of address and topics"}
  defp address_and_topics(address, nil), do: {:ok, %{address_hash: address}}
  defp address_and_topics(nil, topics), do: {:ok, topics}
  defp address_and_topics(address, topics), do: {:ok, Map.put(topics, :address_hash, address)}

  defp validate_address(nil), do: {:ok, nil}

  defp validate_address(address) do
    case Address.cast(address) do
      {:ok, address} -> {:ok, address}
      :error -> {:error, "invalid address"}
    end
  end

  defp validate_topics(nil), do: {:ok, nil}
  defp validate_topics([]), do: []

  defp validate_topics(topics) when is_list(topics) do
    topics
    |> Enum.filter(&(!is_nil(&1)))
    |> Stream.with_index()
    |> Enum.reduce({:ok, %{}}, fn {topic, index}, {:ok, acc} ->
      case cast_topics(topic) do
        {:ok, data} ->
          with_filter = Map.put(acc, String.to_existing_atom("#{@index_to_word[index]}_topic"), data)

          {:ok, add_operator(with_filter, index)}

        :error ->
          {:error, "invalid topics"}
      end
    end)
  end

  defp add_operator(filters, 0), do: filters

  defp add_operator(filters, index) do
    Map.put(filters, String.to_existing_atom("topic#{index - 1}_#{index}_opr"), "and")
  end

  defp cast_topics(topics) when is_list(topics) do
    case EctoType.cast({:array, Data}, topics) do
      {:ok, data} -> {:ok, Enum.map(data, &to_string/1)}
      :error -> :error
    end
  end

  defp cast_topics(topic) do
    case Data.cast(topic) do
      {:ok, data} -> {:ok, to_string(data)}
      :error -> :error
    end
  end

  defp logs_blocks_filter(filter_options) do
    with {:filter, %{"blockHash" => block_hash_param}} <- {:filter, filter_options},
         {:block_hash, {:ok, block_hash}} <- {:block_hash, Hash.Full.cast(block_hash_param)},
         {:block, %{number: number}} <- {:block, Repo.replica().get(Block, block_hash)} do
      {:ok, number, number}
    else
      {:filter, filters} ->
        from_block = Map.get(filters, "fromBlock", "latest")
        to_block = Map.get(filters, "toBlock", "latest")

        max_block_number =
          if from_block == "latest" || to_block == "latest" do
            max_consensus_block_number()
          end

        pending_block_number =
          if from_block == "pending" || to_block == "pending" do
            max_non_consensus_block_number(max_block_number)
          end

        if is_nil(pending_block_number) && from_block == "pending" && to_block == "pending" do
          {:error, :empty}
        else
          to_block_numbers(from_block, to_block, max_block_number, pending_block_number)
        end

      {:block, _} ->
        {:error, "Invalid Block Hash"}

      {:block_hash, _} ->
        {:error, "Invalid Block Hash"}
    end
  end

  defp paging_options(%{
         "paging_options" => %{
           "logIndex" => log_index,
           "blockNumber" => block_number
         }
       }) do
    with {:ok, parsed_block_number} <- to_number(block_number, "invalid block number"),
         {:ok, parsed_log_index} <- to_number(log_index, "invalid log index") do
      {:ok,
       %{
         log_index: parsed_log_index,
         block_number: parsed_block_number
       }}
    end
  end

  defp paging_options(_), do: {:ok, nil}

  defp to_block_numbers(from_block, to_block, max_block_number, pending_block_number) do
    actual_pending_block_number = pending_block_number || max_block_number

    with {:ok, from} <-
           to_block_number(from_block, max_block_number, actual_pending_block_number),
         {:ok, to} <- to_block_number(to_block, max_block_number, actual_pending_block_number) do
      {:ok, from, to}
    end
  end

  defp to_block_number(integer, _, _) when is_integer(integer), do: {:ok, integer}
  defp to_block_number("latest", max_block_number, _), do: {:ok, max_block_number || 0}
  defp to_block_number("earliest", _, _), do: {:ok, 0}
  defp to_block_number("pending", max_block_number, nil), do: {:ok, max_block_number || 0}
  defp to_block_number("pending", _, pending), do: {:ok, pending}

  defp to_block_number("0x" <> number, _, _) do
    case Integer.parse(number, 16) do
      {integer, ""} -> {:ok, integer}
      _ -> {:error, "invalid block number"}
    end
  end

  defp to_block_number(number, _, _) when is_bitstring(number) do
    case Integer.parse(number, 16) do
      {integer, ""} -> {:ok, integer}
      _ -> {:error, "invalid block number"}
    end
  end

  defp to_block_number(_, _, _), do: {:error, "invalid block number"}

  defp to_number(number, error_message) when is_bitstring(number) do
    case Integer.parse(number, 16) do
      {integer, ""} -> {:ok, integer}
      _ -> {:error, error_message}
    end
  end

  defp to_number(_, error_message), do: {:error, error_message}

  defp max_non_consensus_block_number(max) do
    case RPC.max_non_consensus_block_number(max) do
      {:ok, number} -> number
      _ -> nil
    end
  end

  defp max_consensus_block_number do
    case Chain.max_consensus_block_number() do
      {:ok, number} -> number
      _ -> nil
    end
  end

  defp format_success(result, id) do
    %{result: result, id: id}
  end

  defp format_error(message, id) do
    %{error: message, id: id}
  end

  defp do_eth_request(%{"jsonrpc" => rpc_version}) when rpc_version != "2.0" do
    {:error, "invalid rpc version"}
  end

  defp do_eth_request(%{"jsonrpc" => "2.0", "method" => method, "params" => params})
       when is_list(params) do
    with {:ok, action} <- get_action(method),
         {:correct_arity, true} <-
           {:correct_arity, :erlang.function_exported(__MODULE__, action, Enum.count(params))} do
      apply(__MODULE__, action, params)
    else
      {:correct_arity, _} ->
        {:error, "Incorrect number of params."}

      _ ->
        {:error, "Action not found."}
    end
  end

  defp do_eth_request(%{"params" => _params, "method" => _}) do
    {:error, "Invalid params. Params must be a list."}
  end

  defp do_eth_request(_) do
    {:error, "Method, params, and jsonrpc, are all required parameters."}
  end

  defp get_action(action) do
    case Map.get(@methods, action) do
      %{action: action} ->
        {:ok, action}

      _ ->
        :error
    end
  end

  defp block_param("latest"), do: {:ok, :latest}
  defp block_param("earliest"), do: {:ok, :earliest}
  defp block_param("pending"), do: {:ok, :pending}

  defp block_param(string_integer) when is_bitstring(string_integer) do
    case Integer.parse(string_integer) do
      {integer, ""} -> {:ok, integer}
      _ -> :error
    end
  end

  defp block_param(nil), do: {:ok, :latest}
  defp block_param(_), do: :error

  def encode_quantity(%Decimal{} = decimal), do: encode_quantity(Decimal.to_integer(decimal))

  def encode_quantity(binary) when is_binary(binary) do
    hex_binary = Base.encode16(binary, case: :lower)

    result = String.replace_leading(hex_binary, "0", "")

    final_result = if result == "", do: "0", else: result

    "0x#{final_result}"
  end

  def encode_quantity(value) when is_integer(value) do
    value
    |> :binary.encode_unsigned()
    |> encode_quantity()
  end

  def encode_quantity(value) when is_nil(value) do
    nil
  end

  def methods, do: @methods
end
