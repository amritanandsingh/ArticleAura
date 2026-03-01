import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
  CognitoUserAttribute,
} from 'amazon-cognito-identity-js';

const userPool = new CognitoUserPool({
  UserPoolId: process.env.REACT_APP_COGNITO_POOL_ID,
  ClientId: process.env.REACT_APP_CLIENT_ID,
});

function getAttributes(cognitoUser) {
  return new Promise((resolve, reject) => {
    cognitoUser.getUserAttributes((err, attributes) => {
      if (err) return reject(err);
      const user = {};
      attributes.forEach((attr) => { user[attr.getName()] = attr.getValue(); });
      resolve(user);
    });
  });
}

export function signIn(email, password) {
  return new Promise((resolve, reject) => {
    const cognitoUser = new CognitoUser({ Username: email, Pool: userPool });
    const authDetails = new AuthenticationDetails({ Username: email, Password: password });

    cognitoUser.authenticateUser(authDetails, {
      onSuccess: async (session) => {
        try {
          const user = await getAttributes(cognitoUser);
          resolve({ session, user });
        } catch {
          resolve({ session, user: { email } });
        }
      },
      onFailure: (err) => reject(err),
    });
  });
}

export function signUp(email, password, firstName, lastName) {
  return new Promise((resolve, reject) => {
    const attributes = [
      new CognitoUserAttribute({ Name: 'given_name', Value: firstName }),
      new CognitoUserAttribute({ Name: 'family_name', Value: lastName }),
    ];
    userPool.signUp(email, password, attributes, null, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
  });
}

export function confirmSignUp(email, code) {
  return new Promise((resolve, reject) => {
    const cognitoUser = new CognitoUser({ Username: email, Pool: userPool });
    cognitoUser.confirmRegistration(code, true, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
  });
}

export function forgotPassword(email) {
  return new Promise((resolve, reject) => {
    const cognitoUser = new CognitoUser({ Username: email, Pool: userPool });
    cognitoUser.forgotPassword({
      onSuccess: (data) => resolve(data),
      onFailure: (err) => reject(err),
    });
  });
}

export function resetPassword(email, code, newPassword) {
  return new Promise((resolve, reject) => {
    const cognitoUser = new CognitoUser({ Username: email, Pool: userPool });
    cognitoUser.confirmPassword(code, newPassword, {
      onSuccess: () => resolve(),
      onFailure: (err) => reject(err),
    });
  });
}

export function getSession() {
  return new Promise((resolve, reject) => {
    const cognitoUser = userPool.getCurrentUser();
    if (!cognitoUser) return reject(new Error('No current user'));

    cognitoUser.getSession(async (err, session) => {
      if (err || !session.isValid()) return reject(err || new Error('Session invalid'));
      try {
        const user = await getAttributes(cognitoUser);
        resolve({ session, user });
      } catch {
        resolve({ session, user: {} });
      }
    });
  });
}

export function signOut() {
  const cognitoUser = userPool.getCurrentUser();
  if (cognitoUser) cognitoUser.signOut();
}
