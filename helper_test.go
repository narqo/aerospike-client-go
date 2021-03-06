// Copyright 2013-2017 Aerospike, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aerospike

func (clstr *Cluster) GetReadNode(partition *Partition, replica ReplicaPolicy, seq *int) (*Node, error) {
	return clstr.getReadNode(partition, replica, seq)
}

func (clstr *Cluster) GetMasterNode(partition *Partition) (*Node, error) {
	return clstr.getMasterNode(partition)
}

func (p *BatchPolicy) SetBatchDirect(v bool) {
	p.useBatchDirect = v
}
