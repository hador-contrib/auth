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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Xuyuanp/hador"
	"github.com/smartystreets/goconvey/convey"
)

func TestAuth(t *testing.T) {
	convey.Convey("Test Auth", t, func() {
		f := func(req *http.Request) error {
			if req.Header.Get("Authorization") != "" {
				return nil
			}
			return errors.New("Not Authorized")
		}

		h := hador.New()
		h.AddFilters(
			Filter(AuthFunc(f)),
		)

		h.Get("/test", hador.HandlerFunc(func(ctx *hador.Context) {
			ctx.Response.Write([]byte("OK"))
		}))

		convey.Convey("no Authorization", func() {
			req, _ := http.NewRequest("GET", "/test", nil)
			resp := httptest.NewRecorder()

			h.ServeHTTP(resp, req)

			convey.So(resp.Code, convey.ShouldEqual, http.StatusUnauthorized)
			convey.So(resp.Header().Get("WWW-Authenticate"), convey.ShouldNotBeBlank)
		})

		convey.Convey("Authorization", func() {
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "OK")
			resp := httptest.NewRecorder()

			h.ServeHTTP(resp, req)

			convey.So(resp.Code, convey.ShouldEqual, http.StatusOK)
			convey.So(resp.Body.String(), convey.ShouldEqual, "OK")
		})
	})
}
