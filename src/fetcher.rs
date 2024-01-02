use std::prelude::v1::*;

use base::format::debug;
use base::trace::AvgCounter;
use core::marker::PhantomData;
use crypto::keccak_hash;
use eth_tools::ExecutionClient;
use eth_types::{
    BlockHeaderTrait, BlockSelector, FetchState, FetchStateResult, HexBytes,
    TransactionAccessTuple, H160, H256, SH160, SH256, SU256,
};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use statedb::{NoStateFetcher, ProofFetcher, StateFetcher};

#[derive(Debug)]
pub struct BlockStateFetcher<C, E, T>
where
    C: eth_tools::RpcClient,
    E: eth_types::EngineTypes,
    T: AsRef<ExecutionClient<C, E>>,
{
    client: T,
    blk: BlockSelector,
    acc: Option<SH160>,
    counter: AvgCounter,
    phantom: std::marker::PhantomData<(C, E)>,
}

impl<C, E, T> Clone for BlockStateFetcher<C, E, T>
where
    C: eth_tools::RpcClient,
    E: eth_types::EngineTypes,
    T: AsRef<ExecutionClient<C, E>> + Clone,
{
    fn clone(&self) -> Self {
        BlockStateFetcher {
            client: self.client.clone(),
            blk: self.blk.clone(),
            acc: self.acc.clone(),
            counter: self.counter.clone(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<C, E, T> BlockStateFetcher<C, E, T>
where
    C: eth_tools::RpcClient,
    E: eth_types::EngineTypes,
    T: AsRef<ExecutionClient<C, E>>,
{
    pub fn new(client: T, blk: BlockSelector) -> Self {
        Self {
            client,
            acc: None,
            blk,
            counter: AvgCounter::new(),
            phantom: std::marker::PhantomData,
        }
    }

    fn client(&self) -> &ExecutionClient<C, E> {
        self.client.as_ref()
    }
}

impl<C, E, T> StateFetcher for BlockStateFetcher<C, E, T>
where
    C: eth_tools::RpcClient,
    E: eth_types::EngineTypes,
    T: AsRef<ExecutionClient<C, E>> + Clone,
{
    fn with_acc(&self, address: &SH160) -> Self {
        let mut storage_fetcher = self.clone();
        storage_fetcher.acc = Some(address.clone());
        storage_fetcher
    }

    fn fork(&self) -> Self {
        self.clone()
    }

    fn get_block_hash(&self, number: u64) -> Result<SH256, statedb::Error> {
        let _counter = self.counter.place();

        let header = self
            .client()
            .get_block_header(number.into())
            .map_err(|err| statedb::Error::CallRemoteFail(format!("[get_block_hash] {:?}", err)))?;
        Ok(header.hash())
    }

    fn get_account(&self, address: &SH160) -> Result<(SU256, u64, HexBytes), statedb::Error> {
        let _counter = self.counter.place();

        let fetch_state = FetchState {
            access_list: Some(Cow::Owned(TransactionAccessTuple {
                address: address.clone(),
                storage_keys: Vec::new(),
            })),
            code: Some(address.clone()),
        };
        let result = self
            .client()
            .fetch_states(&[fetch_state], self.blk, false)
            .map_err(|err| statedb::Error::CallRemoteFail(format!("{:?}", err)))?
            .pop()
            .unwrap();
        let acc = result.acc.unwrap();
        Ok((acc.balance, acc.nonce.as_u64(), result.code.unwrap()))
    }

    fn get_storage(&self, address: &SH160, key: &SH256) -> Result<SH256, statedb::Error> {
        let _counter = self.counter.place();

        Ok(self
            .client()
            .get_storage(address, key, self.blk)
            .map_err(|err| statedb::Error::CallRemoteFail(format!("{:?}", err)))?)
    }

    fn get_code(&self, address: &SH160) -> Result<HexBytes, statedb::Error> {
        let _counter = self.counter.place();

        let code = self
            .client()
            .get_code(address, self.blk)
            .map_err(|err| statedb::Error::CallRemoteFail(format!("[get_block_hash] {:?}", err)))?;
        Ok(code)
    }

    fn prefetch_states(
        &self,
        list: &[FetchState],
        with_proof: bool,
    ) -> Result<Vec<FetchStateResult>, statedb::Error> {
        self.client()
            .fetch_states(list, self.blk, with_proof)
            .map_err(|err| statedb::Error::CallRemoteFail(format!("[get_block_hash] {:?}", err)))
    }

    fn get_miss_usage(&self) -> base::trace::AvgCounterResult {
        self.counter.take()
    }
}

impl<C, E, T> ProofFetcher for BlockStateFetcher<C, E, T>
where
    C: eth_tools::RpcClient,
    E: eth_types::EngineTypes,
    T: AsRef<ExecutionClient<C, E>>,
{
    fn fetch_proofs(&self, key: &[u8]) -> Result<Vec<HexBytes>, String> {
        let _counter = self.counter.place();
        glog::debug!(exclude: "dry_run", target: "state_fetch", "fetch proof: acc[{:?}] {}", self.acc, HexBytes::from(key));
        match &self.acc {
            Some(acc) => {
                assert_eq!(key.len(), 32);
                let key = H256::from_slice(key).into();
                let result = self
                    .client()
                    .get_proof(acc, &[key], self.blk)
                    .map_err(debug)?;
                let storage = result.storage_proof.into_iter().next().unwrap();
                Ok(storage.proof)
            }
            None => {
                assert_eq!(key.len(), 20);
                let account = H160::from_slice(key).into();
                let result = self
                    .client()
                    .get_proof(&account, &[], self.blk)
                    .map_err(debug)?;
                Ok(result.account_proof)
            }
        }
    }

    fn get_nodes(&self, node: &[SH256]) -> Result<Vec<HexBytes>, String> {
        let _counter = self.counter.place();

        self.client()
            .get_dbnodes(node)
            .map_err(|err| format!("{:?}", err))
    }
}

#[derive(Clone)]
pub struct StateCollector<C, E, T>
where
    C: eth_tools::RpcClient,
    E: eth_types::EngineTypes,
    T: AsRef<ExecutionClient<C, E>>,
{
    fetcher: BlockStateFetcher<C, E, T>,
    nodes: Arc<Mutex<BTreeMap<SH256, HexBytes>>>,
}

impl<C, E, T> StateCollector<C, E, T>
where
    C: eth_tools::RpcClient,
    E: eth_types::EngineTypes,
    T: AsRef<ExecutionClient<C, E>>,
{
    pub fn new(client: T, blk: BlockSelector) -> Self {
        Self {
            fetcher: BlockStateFetcher::new(client, blk),
            nodes: Default::default(),
        }
    }

    pub fn take(&mut self) -> BTreeMap<SH256, HexBytes> {
        let mut nodes = self.nodes.lock().unwrap();
        let mut new = BTreeMap::new();
        std::mem::swap(&mut new, &mut nodes);
        new
    }
}

impl<C, E, T> ProofFetcher for StateCollector<C, E, T>
where
    C: eth_tools::RpcClient,
    E: eth_types::EngineTypes,
    T: AsRef<ExecutionClient<C, E>>,
{
    fn fetch_proofs(&self, key: &[u8]) -> Result<Vec<HexBytes>, String> {
        let nodes = self.fetcher.fetch_proofs(key)?;
        {
            let mut caches = self.nodes.lock().unwrap();
            for node in &nodes {
                let hash = keccak_hash(&node).into();
                caches.insert(hash, node.clone());
            }
        }
        Ok(nodes)
    }

    fn get_nodes(&self, node: &[SH256]) -> Result<Vec<HexBytes>, String> {
        let results = self.fetcher.get_nodes(node)?;
        {
            let mut nodes = self.nodes.lock().unwrap();
            for (idx, item) in node.iter().enumerate() {
                nodes.insert(*item, results[idx].clone());
            }
        }
        Ok(results)
    }
}

impl<C, E, T> StateFetcher for StateCollector<C, E, T>
where
    C: eth_tools::RpcClient + Clone,
    E: eth_types::EngineTypes + Clone,
    T: AsRef<ExecutionClient<C, E>> + Clone,
{
    fn fork(&self) -> Self {
        self.clone()
    }

    fn get_account(&self, address: &SH160) -> Result<(SU256, u64, HexBytes), statedb::Error> {
        ().get_account(address)
    }

    fn get_block_hash(&self, number: u64) -> Result<SH256, statedb::Error> {
        ().get_block_hash(number)
    }

    fn get_code(&self, address: &SH160) -> Result<HexBytes, statedb::Error> {
        ().get_code(address)
    }

    fn get_miss_usage(&self) -> base::trace::AvgCounterResult {
        ().get_miss_usage()
    }

    fn get_storage(&self, address: &SH160, key: &SH256) -> Result<SH256, statedb::Error> {
        ().get_storage(address, key)
    }

    fn prefetch_states(
        &self,
        list: &[FetchState],
        with_proof: bool,
    ) -> Result<Vec<FetchStateResult>, statedb::Error> {
        ().prefetch_states(list, with_proof)
    }

    fn with_acc(&self, address: &SH160) -> Self {
        let fetcher = self.fetcher.with_acc(address);
        Self {
            fetcher,
            nodes: self.nodes.clone(),
        }
    }
}
