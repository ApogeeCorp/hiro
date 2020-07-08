import React, { useState } from 'react';
import { Redirect } from 'react-router-dom';
import { useCookies } from 'react-cookie';

import auth from '../Auth';

const Login = (props) => {
  // check if this a successfull redirect back
  const auth_code = new URLSearchParams(props.location.search).get('code');
  const err = new URLSearchParams(props.location.search).get('error');
  var username = undefined;
  const req_token = new URLSearchParams(props.location.search).get(
    'request_token',
  );

  if (err !== null && err != 'access_denied') {
    console.log(auth_code);

    return (
      <Redirect
        to={{
          pathname: '/',
          state: {
            from: props.location,
          },
        }}
      />
    );
  }

  if (auth_code !== null) {
    // TODO: auth succeeded, request the OAUTH TOKEN HERE
    console.log('auth_code=' + auth_code);
    return (
      <Redirect
        to={{
          pathname: '/',
          state: {
            from: props.location,
          },
        }}
      />
    );
  }

  return (
    <div>
      <h1>Login Page</h1>
      <form id="login" name="login" action="/oauth/login" method="POST">
        <label htmlFor="username">Username</label>
        <input type="text" id="username" name="username" />
        <br />
        <label htmlFor="password">Password</label>
        <input type="password" id="password" name="password" />
        <input type="submit" value="Submit" />
        <input
          type="hidden"
          id="code_verifier"
          name="code_verifier"
          value={auth.verifier()}
        />
        <input
          type="hidden"
          id="request_token"
          name="request_token"
          value={req_token || undefined}
        />
      </form>
    </div>
  );
};

export default Login;
