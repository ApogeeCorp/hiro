# Hiro Oauth 2.0

This package provides a base OAuth 2.0 implementation for Model Rocket projects.

The comsumer only needs to implements the `Controller` and associated interfaces to provide backend storage for tokens and other objects.

The package provides a `Routes` set that is designed to be used with the [api.Server](../api/README.md) package, which can extend another api service adding authentication support.