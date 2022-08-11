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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt"
)

const (
	WsScheme  = "ws"
	WssScheme = "wss"
	BufSize   = 1024 * 32
)

var ErrFormatAddr = errors.New("remote websockets addr format error")

type WebsocketProxy struct {
	// ws, wss
	scheme string
	// The target address: host:port
	remoteAddr string
	// path
	defaultPath string
	tlsc        *tls.Config
	logger      *log.Logger
	// Send handshake before callback
	beforeHandshake func(r *http.Request) error
	// Auth
	oidc OidcConfig
}

type OidcConfig struct {
	jwk_url      string
	aud          string
	token_prefix string
}

type Options func(wp *WebsocketProxy)

// You must carry a port number，ws://ip:80/ssss, wss://ip:443/aaaa
// ex: ws://ip:port/ajaxchattest
func NewProxy(addr string, jwk_url string, aud string, token_prefix string, beforeCallback func(r *http.Request) error, options ...Options) (*WebsocketProxy, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, ErrFormatAddr
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, ErrFormatAddr
	}
	if u.Scheme != WsScheme && u.Scheme != WssScheme {
		return nil, ErrFormatAddr
	}

	oidc := OidcConfig{}
	oidc.token_prefix = token_prefix

	if len(jwk_url) > 0 {
		oidc.jwk_url = jwk_url
	}

	if len(aud) > 0 {
		oidc.aud = aud
	}

	wp := &WebsocketProxy{
		scheme:          u.Scheme,
		remoteAddr:      fmt.Sprintf("%s:%s", host, port),
		defaultPath:     u.Path,
		beforeHandshake: beforeCallback,
		logger:          log.New(os.Stderr, "", log.LstdFlags),
		oidc:            oidc,
	}

	if u.Scheme == WssScheme {
		wp.tlsc = &tls.Config{InsecureSkipVerify: true}
	}
	for op := range options {
		options[op](wp)
	}
	return wp, nil
}

func (wp *WebsocketProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	wp.Proxy(writer, request)
}

func (wp *WebsocketProxy) ValidateJWT(writer http.ResponseWriter, headers http.Header) error {
	jwtToken, ok := headers["Authorization"]

	if !ok {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Missing authorization header"))
		return errors.New("Missing authorization header")
	}

	idToken := strings.Join(jwtToken, " ")

	if len(idToken) < len(wp.oidc.token_prefix) || !strings.HasPrefix(idToken, wp.oidc.token_prefix+" ") {
		log.Println("Bad token prefix")
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Bad token prefix"))
		return errors.New("Bad token prefix")
	}

	idToken = strings.ReplaceAll(idToken, " ", "")
	idToken = idToken[utf8.RuneCountInString(wp.oidc.token_prefix):]

	claims := jwt.MapClaims{}
	jwt.ParseWithClaims(idToken, claims, nil)

	// is that secure???
	if len(wp.oidc.aud) == 0 {
		wp.oidc.aud = claims["aud"].(string)
	}

	oidcConfig := oidc.Config{
		ClientID: wp.oidc.aud,
	}

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, wp.oidc.jwk_url)
	if err != nil {
		log.Println(err)
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Bad token validator url"))
		return errors.New("Bad token validator url")
	}

	verifier := provider.Verifier(&oidcConfig)

	// is that enough???
	_, err = verifier.Verify(ctx, idToken)
	if err != nil {
		log.Println(err)
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Bad token validator url"))
		return errors.New("Bad token validator url")
	}

	return nil
}

func (wp *WebsocketProxy) Proxy(writer http.ResponseWriter, request *http.Request) {

	// is that secure???
	request.Header.Del("Origin")

	if len(wp.oidc.jwk_url) > 0 {
		err := wp.ValidateJWT(writer, request.Header)
		if err != nil {
			return
		}
	}

	if !strings.Contains(strings.ToLower(request.Header.Get("Connection")), "upgrade") ||
		strings.ToLower(request.Header.Get("Upgrade")) != "websocket" {
		_, _ = writer.Write([]byte(`Must be a websocket request`))
		return
	}

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	req := request.Clone(request.Context())
	req.URL.Path, req.URL.RawPath, req.RequestURI = wp.defaultPath, wp.defaultPath, wp.defaultPath
	req.Host = wp.remoteAddr
	if wp.beforeHandshake != nil {
		// Add headers, permission authentication + masquerade sources
		err = wp.beforeHandshake(req)
		if err != nil {
			_, _ = writer.Write([]byte(err.Error()))
			return
		}
	}

	var remoteConn net.Conn
	switch wp.scheme {
	case WsScheme:
		remoteConn, err = net.Dial("tcp", wp.remoteAddr)
	case WssScheme:
		remoteConn, err = tls.Dial("tcp", wp.remoteAddr, wp.tlsc)
	}
	if err != nil {
		_, _ = writer.Write([]byte(err.Error()))
		return
	}
	defer remoteConn.Close()
	err = req.Write(remoteConn)
	if err != nil {
		wp.logger.Println("remote write err:", err)
		return
	}
	errChan := make(chan error, 2)
	copyConn := func(a, b net.Conn) {
		buf := ByteSliceGet(BufSize)
		defer ByteSlicePut(buf)
		_, err := io.CopyBuffer(a, b, buf)
		errChan <- err
	}
	go copyConn(conn, remoteConn) // response
	go copyConn(remoteConn, conn) // request
	select {
	case err = <-errChan:
		if err != nil {
			log.Println(err)
		}
	}
}

func SetTLSConfig(tlsc *tls.Config) Options {
	return func(wp *WebsocketProxy) {
		wp.tlsc = tlsc
	}
}

func SetLogger(l *log.Logger) Options {
	return func(wp *WebsocketProxy) {
		if l != nil {
			wp.logger = l
		}
	}
}
