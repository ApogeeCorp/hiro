import React from 'react';

import { BrowserRouter as Router, Switch, Route } from 'react-router-dom';
import ProtectedRoute from './ProtectedRoute';

import Dashboard from './components/Dashboard';
import Landing from './components/Landing';
import Login from './components/Login';

const App = () => {
  return (
    <Router>
      <Switch>
        <Route
          exact
          path="/"
          component={(props) => (
            <Landing
              {...props}
              auth_url="/oauth/authorize"
              login_uri="/login"
              client_id="Xazhwq3L6uDz4K9ZcsPWKT"
              scope="offline_access openid profile property:read"
              audience="teralytic:api"
            />
          )}
        />
        <Route
          exact
          path="/login"
          component={(props) => <Login {...props} />}
        />
        <ProtectedRoute exact path="/Dashboard" component={Dashboard} />
      </Switch>
    </Router>
  );
};

export default App;
