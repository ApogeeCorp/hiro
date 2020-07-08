import React from 'react';
import auth from '../Auth';

const Dashboard = (props) => {
  return (
    <div>
      <h1>Dashboard</h1>
      <button
        onClick={() => {
          auth.logout(() => {
            props.history.push('/');
          });
        }}
      >
        Logout
      </button>
    </div>
  );
};

export default Dashboard;
