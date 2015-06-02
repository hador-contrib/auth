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

// ErrorKey is the key of unauthorized error in context
const ErrorKey = "github.com/hador-contrib/auth.Error"

// Func is a function to check authorized
type Func func(*http.Request) error

func (f Func) Auth(req *http.Request) error {
	return f(req)
}

// Filter filters request by AuthFunc
func Filter(f Func) hador.FilterFunc {
	return func(ctx *hador.Context, next hador.Handler) {
		err := f.Auth(ctx.Request)
		if err != nil {
			ctx.Response.Header().Set("WWW-Authenticate", err.Error())
			ctx.OnError(http.StatusUnauthorized, err)
			return
		}
		next.Serve(ctx)
	}
}
