// Copyright (c) 2021 Quark Container Authors / 2014 The Kubernetes Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

#[macro_use]
extern crate log;
extern crate simple_logging;

pub mod types;
pub mod common;
pub mod selector;
pub mod selection_predicate;
pub mod validation;
pub mod cacher_client;
//pub mod fifo;
pub mod store;
//pub mod delta_fifo;
pub mod informer;
pub mod informer_factory;
//pub mod core_types;
pub mod runtime_types;
pub mod k8s_util;
pub mod qservice;

// workaround to address the pb generated structure serde_json issue
pub mod pb_gen;

pub mod config;

pub mod service_directory {
    include!("pb_gen/service_directory.rs");
}
