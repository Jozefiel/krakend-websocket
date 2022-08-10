/*
 *	* Copyright 2022 pretty66/websocketproxy
 *  *
 *  * Licensed to the Apache Software Foundation (ASF) under one or more
 *  * contributor license agreements.  See the NOTICE file distributed with
 *  * this work for additional information regarding copyright ownership.
 *  * The ASF licenses this file to You under the Apache License, Version 2.0
 *  * (the "License"); you may not use this file except in compliance with
 *  * the License.  You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package websocketproxy

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestNewWebsocketProxy(t *testing.T) {
	tlsc := tls.Config{InsecureSkipVerify: true}
	wp, err := NewProxy("ws://www.baidu.com:80/ajaxchattest", auth, SetTLSConfig(&tlsc))
	if err != nil {
		t.Fatal(err)
	}
	http.HandleFunc("/wsproxy", wp.Proxy)
	http.ListenAndServe(":9696", nil)
}

func TestNewHandler(t *testing.T) {
	tlsc := tls.Config{InsecureSkipVerify: true}
	wp, err := NewProxy("ws://www.baidu.com:80/ajaxchattest", auth, SetTLSConfig(&tlsc))
	if err != nil {
		t.Fatal(err)
	}
	http.ListenAndServe(":9696", wp)
}

func auth(r *http.Request) error {
	// Permission to verify
	r.Header.Set("Cookie", "----")
	// Source of disguise
	r.Header.Set("Origin", "http://82.157.123.54:9010")
	return nil
}
