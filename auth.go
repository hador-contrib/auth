/*
 * Copyright 2015 Xuyuan Pang
 * Author: Xuyuan Pang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

import (
	"net/http"

	"github.com/Xuyuanp/hador"
)

// Authenticator interface.
type Authenticator interface {
	Auth(*http.Request) error
}

// AuthFunc is a function to check authorized.
type AuthFunc func(*http.Request) error

// Auth implements Authenticator interface by calls function f.
func (f AuthFunc) Auth(req *http.Request) error {
	return f(req)
}

// Filter filters request by Authenticator.
func Filter(a Authenticator) hador.FilterFunc {
	return func(ctx *hador.Context, next hador.Handler) {
		err := a.Auth(ctx.Request)
		if err != nil {
			ctx.Response.Header().Set("WWW-Authenticate", err.Error())
			ctx.OnError(http.StatusUnauthorized, err)
			return
		}
		next.Serve(ctx)
	}
}
