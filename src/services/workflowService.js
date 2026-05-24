const NETWORK_ERROR_MESSAGE =
  'Unable to reach the workflow API. Check your connection and confirm the workflow endpoint allows this site in CORS for the requested HTTP method.';

function getWorkflowApiUrl() {
  return (process.env.REACT_APP_HOME_PAGE_URL || '').trim();
}

function buildWorkflowRequestUrl(apiUrl, email) {
  const baseUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost';
  const hasEmailPlaceholder = /\{email\}/i.test(apiUrl);
  const workflowUrl = hasEmailPlaceholder
    ? apiUrl.replace(/\{email\}/gi, encodeURIComponent(email))
    : apiUrl;

  try {
    const url = new URL(workflowUrl, baseUrl);
    if (!hasEmailPlaceholder) {
      url.searchParams.set('email', email);
    }

    return url.toString();
  } catch {
    throw new Error('Workflow API URL is invalid.');
  }
}

function buildWorkflowError(data, status) {
  const code = data?.error?.code || data?.code || 'UNKNOWN_ERROR';
  const message =
    data?.error?.message ||
    data?.message ||
    `Workflow request failed (${status}).`;
  const requestId = data?.error?.requestId || data?.requestId;

  const err = new Error(message);
  err.code = code;
  err.status = status;
  if (requestId) err.requestId = requestId;
  return err;
}

async function parseWorkflowResponse(response) {
  let data;

  try {
    data = await response.json();
  } catch {
    throw new Error('Workflow API returned a non-JSON response. Check the configured workflow endpoint URL.');
  }

  if (response.status === 404 && (data === 'Not found' || data?.message === 'Not found')) {
    return { workflows: [], meta: null };
  }

  if (!response.ok || data?.success === false) {
    throw buildWorkflowError(data, response.status);
  }

  if (Array.isArray(data)) {
    return { workflows: data, meta: null };
  }

  const workflows = Array.isArray(data?.workflows) ? data.workflows : [];
  const meta = data?.meta || null;
  return { workflows, meta };
}

async function workflowFetch(requestUrl, options) {
  let response;
  try {
    response = await fetch(requestUrl, options);
  } catch (err) {
    if (err?.name === 'TypeError' || /failed to fetch|network/i.test(err?.message || '')) {
      throw new Error(NETWORK_ERROR_MESSAGE);
    }
    throw err;
  }
  return parseWorkflowResponse(response);
}

export async function getWorkflows(email, token) {
  const apiUrl = getWorkflowApiUrl();
  if (!apiUrl) {
    throw new Error('Workflow API URL is not configured.');
  }

  const requestUrl = buildWorkflowRequestUrl(apiUrl, email);
  const headers = token ? { Authorization: `Bearer ${token}` } : undefined;

  return workflowFetch(requestUrl, {
    method: 'GET',
    ...(headers ? { headers } : {}),
  });
}

export async function saveWorkflows(email, token, workflows) {
  const apiUrl = getWorkflowApiUrl();
  if (!apiUrl) {
    throw new Error('Workflow API URL is not configured.');
  }

  const requestUrl = buildWorkflowRequestUrl(apiUrl, email);
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  return workflowFetch(requestUrl, {
    method: 'PUT',
    headers,
    body: JSON.stringify({ workflows }),
  });
}

export async function fetchWorkflowsForEmail(email, token) {
  const { workflows } = await getWorkflows(email, token);
  return workflows;
}
