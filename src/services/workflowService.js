const NETWORK_ERROR_MESSAGE =
  'Unable to reach the workflow API. Check that the production workflow endpoint allows this site in CORS and permits OPTIONS preflight requests with Authorization.';

function getWorkflowApiUrl() {
  return (process.env.REACT_APP_WORKFLOWS_URL || process.env.REACT_APP_HOME_PAGE_URL || '').trim();
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

async function parseWorkflowResponse(response) {
  let data;

  try {
    data = await response.json();
  } catch {
    throw new Error('Workflow API returned a non-JSON response. Check the configured workflow endpoint URL.');
  }

  if (!response.ok) {
    throw new Error(data?.message || `Workflow request failed (${response.status})`);
  }

  if (Array.isArray(data)) {
    return data;
  }

  if (data?.success === false) {
    throw new Error(data.message || 'Failed to load workflows.');
  }

  return Array.isArray(data?.workflows) ? data.workflows : [];
}

export async function fetchWorkflowsForEmail(email, token) {
  const apiUrl = getWorkflowApiUrl();
  if (!apiUrl) {
    throw new Error('Workflow API URL is not configured.');
  }

  const requestUrl = buildWorkflowRequestUrl(apiUrl, email);
  const headers = token ? { Authorization: `Bearer ${token}` } : undefined;

  let response;
  try {
    response = await fetch(requestUrl, {
      method: 'GET',
      ...(headers ? { headers } : {}),
    });
  } catch (err) {
    if (err?.name === 'TypeError' || /failed to fetch|network/i.test(err?.message || '')) {
      throw new Error(NETWORK_ERROR_MESSAGE);
    }

    throw err;
  }

  return parseWorkflowResponse(response);
}
