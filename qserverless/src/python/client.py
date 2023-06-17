# Copyright (c) 2021 Quark Container Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import grpc
import uuid
import os
import numpy as np
import janus

import func_pb2_grpc
import func_pb2
import blob_mgr
import func
import common

from func_pb2_grpc import *
from func_pb2 import *

funcAgentQueueTx = asyncio.Queue(100)
funcMgr = None

EnvVarNodeMgrPodId      = "qserverless_podid";
EnvVarNodeMgrNamespace  = "qserverless_namespace";
EnvVarNodeMgrPackageId  = "qserverless_packageid";
EnvVarNodeAgentAddr     = "qserverless_nodeagentaddr";
DefaultNodeAgentAddr    = "unix:///var/lib/quark/nodeagent/sock";

async def generate_messages():
    while True:
        item = await funcAgentQueueTx.get()
        yield item

def GetPodIdFromEnvVar() :
    podId = os.getenv(EnvVarNodeMgrPodId)
    if podId is None:
        podId = str(uuid.uuid4())
        return podId
    else :
        return podId
    
def GetNamespaceFromEnvVar() :
    ns = os.getenv(EnvVarNodeMgrNamespace)
    if ns is None :
        return ""
    return ns
    
def GetPackageIdFromEnvVar() :
    pid = os.getenv(EnvVarNodeMgrPackageId)
    if pid is None :
        return ""
    return pid

def GetNodeAgentAddrFromEnvVar() :
    pid = os.getenv(EnvVarNodeAgentAddr)
    if pid is None :
        return DefaultNodeAgentAddr
    return pid


class FuncCallContext:
    def __init__(self, jobId: str, id: str):
        self.jobId = jobId
        self.id = id
        
    def NewTaskContext(self) :
        id = str(uuid.uuid4())
        return FuncCallContext(self.jobId, id)
    
    async def RemoteCall(
        self,
        packageName: str, 
        funcName: str, 
        parameters: str, 
        priority: int
        ) -> common.CallResult: 
        taskContext = self.NewTaskContext();
        
        return await funcMgr.RemoteCall(taskContext, packageName, funcName, parameters, priority)
    
    async def BlobCreate(self, name: str) -> common.CallResult: 
        return await funcMgr.blob_mgr.BlobCreate(name)
    
    async def BlobWrite(self, id: np.uint64, buf: bytes) -> common.CallResult:
        return await funcMgr.blob_mgr.BlobWrite(id, buf)
    
    async def BlobOpen(self, addr: common.BlobAddr) -> common.CallResult:
        return await funcMgr.blob_mgr.BlobOpen(addr)
    
    async def BlobDelete(self, svcAddr: str, name: str) -> common.CallResult:
        return await funcMgr.blob_mgr.BlobDelete(svcAddr, name)
    
    async def BlobRead(self, id: np.uint64, len: np.uint64) -> common.CallResult:
        return await funcMgr.blob_mgr.BlobRead(id, len)
    
    async def BlobSeek(self, id: np.uint64, seekType: int, pos: np.int64) -> common.CallResult:
        return await funcMgr.blob_mgr.BlobSeek(id, seekType, pos)
    
    async def BlobClose(self, id: np.uint64) -> common.CallResult:
        return await funcMgr.blob_mgr.BlobClose(id)

def NewJobContext() -> FuncCallContext :
    id = str(uuid.uuid4())
    return FuncCallContext(id, id)

class FuncMgr:
    def __init__(self, svcAddr: str, namespace: str, packageName: str):
        self.funcPodId = GetPodIdFromEnvVar()
        self.namespace = namespace
        self.packageName = packageName
        self.reqQueue = asyncio.Queue(100)
        self.clientQueue = funcAgentQueueTx
        self.callerCalls = dict()
        self.blob_mgr = blob_mgr.BlobMgr(funcAgentQueueTx)
        self.svcAddr = svcAddr
        blob_mgr.blobMgr = self
    
    async def RemoteCall(
        self,
        context: FuncCallContext,
        packageName: str, 
        funcName: str, 
        parameters: str, 
        priority: int
        ) -> common.CallResult: 
        
        if packageName == "" :
            packageName = self.packageName
        
        id = context.id
        req = func_pb2.FuncAgentCallReq (
            jobId = context.jobId,
            id = context.id,
            namespace = self.namespace,
            packageName = packageName,
            funcName = funcName,
            parameters = parameters,
            priority = priority
        )
        callQueue = janus.Queue() #asyncio.Queue(1)
        self.callerCalls[id] = callQueue
        self.clientQueue.put_nowait(func_pb2.FuncAgentMsg(msgId=0, FuncAgentCallReq=req))
        res = await callQueue.async_q.get()
        return res
    
    async def BlobCreate(self, name: str) -> common.CallResult: 
        return await self.blob_mgr.BlobCreate(name)
    
    async def BlobWrite(self, id: np.uint64, buf: bytes) -> common.CallResult:
        return await self.blob_mgr.BlobWrite(id, buf)
    
    async def BlobOpen(self, addr: common.BlobAddr) -> common.CallResult:
        return await self.blob_mgr.BlobOpen(addr)
    
    async def BlobDelete(self, svcAddr: str, name: str) -> common.CallResult:
        return await self.blob_mgr.BlobDelete(svcAddr, name)
    
    async def BlobRead(self, id: np.uint64, len: np.uint64) -> common.CallResult:
        return await self.blob_mgr.BlobRead(id, len)
    
    async def BlobSeek(self, id: np.uint64, seekType: int, pos: np.int64) -> common.CallResult:
        return await self.blob_mgr.BlobSeek(id, seekType, pos)
    
    async def BlobClose(self, id: np.uint64) -> common.CallResult:
        return await self.blob_mgr.BlobClose(id)
    
    def CallRespone(self, id: str, res: common.CallResult) :
        callQueue = self.callerCalls.get(id)
        if callQueue is None:
            return
        
        callQueue.async_q.put_nowait(res)
        self.callerCalls.pop(id)
        
    def LocalCall(self, req: func_pb2.FuncAgentCallReq) :
        self.reqQueue.put_nowait(req)
        
    async def FuncCall(self, context: FuncCallContext, name: str, parameters: str) -> common.CallResult:
        function = getattr(func, name)
        if function is None:
            return common.CallResult("", "There is no func named {}".format(name))
        result = await function(context, parameters)
        return common.CallResult(result, "")
    
    def Close(self) : 
        self.reqQueue.put_nowait(None)
    
    async def Process(self) :
        while True :
            req = await self.reqQueue.get();
            if req is None:
                break
            context = FuncCallContext(req.jobId, req.id)
            res = await self.FuncCall(context, req.funcName, req.parameters)
            resp = func_pb2.FuncAgentCallResp(id=req.id, resp=res.res, error=res.error)
            self.clientQueue.put_nowait(func_pb2.FuncAgentMsg(msgId=2, FuncAgentCallResp=resp))
            
    async def FuncAgentClientProcess(self, msg: func_pb2.FuncAgentMsg):
            msgType = msg.WhichOneof('EventBody')
            match msgType:
                case 'FuncAgentCallReq' :
                    req = msg.FuncAgentCallReq
                    self.LocalCall(req)
                case 'FuncAgentCallResp':
                    resp = msg.FuncAgentCallResp
                    res = common.CallResult(res=resp.resp, error=resp.error)
                    self.CallRespone(resp.id, res)
                case _ :
                    self.blob_mgr.OnFuncAgentMsg(msg)
                    
    async def StartClientProcess(self):
        print("start to connect addr ", self.svcAddr)
        async with grpc.aio.insecure_channel(self.svcAddr) as channel:
            stub = FuncAgentServiceStub(channel)
            responses = stub.StreamProcess(generate_messages())
            async for response in responses:
                await self.FuncAgentClientProcess(response)

def Register(svcAddr: str, namespace: str, packageName: str, clientMode: bool):
    global funcMgr
    funcMgr = FuncMgr(svcAddr, namespace, packageName)  
    podId = str(uuid.uuid4())
    regReq = func_pb2.FuncPodRegisterReq(funcPodId=podId,namespace=namespace,packageName=packageName, clientMode= clientMode)
    req = func_pb2.FuncAgentMsg(msgId=1, FuncPodRegisterReq=regReq)
    funcAgentQueueTx.put_nowait(func_pb2.FuncAgentMsg(msgId=1, FuncPodRegisterReq=regReq))


async def StartSvc():
    agentClientTask = asyncio.create_task(funcMgr.StartClientProcess())
    await funcMgr.Process()


if __name__ == '__main__':
    namespace = GetNamespaceFromEnvVar()
    packageId = GetPackageIdFromEnvVar()
    svcAddr = GetNodeAgentAddrFromEnvVar()
    print("namespace = ", namespace, " packageId =", packageId, " svcAddr = ", svcAddr)
    Register(svcAddr, namespace, packageId, False)
    asyncio.run(StartSvc())

def Call(svcAddr: str, namespace: str, packageName: str, funcName: str, parameters: str) -> common.CallResult:
    id = str(uuid.uuid4())
    req = func_pb2.FuncAgentCallReq (
        jobId = id,
        id = id,
        namespace = namespace,
        packageName = packageName,
        funcName = funcName,
        parameters = parameters,
        priority = 1
    )
    
    channel = grpc.insecure_channel(svcAddr)
    stub = FuncAgentServiceStub(channel)
    
    res = stub.FuncCall(req)
    return common.CallResult(res.resp, res.error)
    