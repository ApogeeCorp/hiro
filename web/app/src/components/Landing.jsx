import React from 'react';
import auth from '../Auth';

const Landing = ({ auth_url, client_id, scope, audience, login_uri }) => {
  return (
    <div>
      <h1>Landing Page</h1>
      <button
        onClick={() =>
          auth.login(auth_url, client_id, scope, audience, login_uri)
        }
      >
        Login
      </button>
    </div>
  );
};

export default Landing;
