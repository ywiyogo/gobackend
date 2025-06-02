package registry

import (
	"net/http"
)

type Route struct {
	Pattern string
	Handler http.HandlerFunc
}

var routes []Route

func Register(pattern string, handler http.HandlerFunc) {
	routes = append(routes, Route{pattern, handler})
}

func BuildRouter() http.Handler {
	mux := http.NewServeMux()
	for _, r := range routes {
		mux.HandleFunc(r.Pattern, r.Handler)
	}
	return mux
}
