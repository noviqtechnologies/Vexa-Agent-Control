import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { api, subscribeAlerts, setAuthToken } from './client'

function mockFetch(body: unknown, ok = true, status = 200) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  })
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('api.getFleetOverview', () => {
  it('fetches fleet stats', async () => {
    const stats = { total_agents: 5, active_agents: 3 }
    global.fetch = mockFetch(stats)

    const result = await api.getFleetOverview()
    expect(result).toEqual(stats)
    expect(fetch).toHaveBeenCalledWith('/api/v1/fleet/overview', { headers: {} })
  })

  it('throws on non-ok response', async () => {
    global.fetch = mockFetch('server error', false, 500)

    await expect(api.getFleetOverview()).rejects.toThrow('API 500')
  })
})

describe('api.listAgents', () => {
  it('uses default pagination', async () => {
    global.fetch = mockFetch([])

    await api.listAgents()
    expect(fetch).toHaveBeenCalledWith('/api/v1/fleet/agents?limit=50&offset=0', { headers: {} })
  })

  it('passes custom pagination', async () => {
    global.fetch = mockFetch([])

    await api.listAgents(10, 20)
    expect(fetch).toHaveBeenCalledWith('/api/v1/fleet/agents?limit=10&offset=20', { headers: {} })
  })
})

describe('api.getHeatmap', () => {
  it('uses default 24 hours', async () => {
    global.fetch = mockFetch([])

    await api.getHeatmap()
    expect(fetch).toHaveBeenCalledWith('/api/v1/fleet/heatmap?hours=24', { headers: {} })
  })

  it('passes custom hours', async () => {
    global.fetch = mockFetch([])

    await api.getHeatmap(48)
    expect(fetch).toHaveBeenCalledWith('/api/v1/fleet/heatmap?hours=48', { headers: {} })
  })
})

describe('api.listCredentials', () => {
  it('fetches all credentials without filter', async () => {
    global.fetch = mockFetch([])

    await api.listCredentials()
    expect(fetch).toHaveBeenCalledWith('/api/v1/identity/credentials', { headers: {} })
  })

  it('filters by agent_id', async () => {
    global.fetch = mockFetch([])

    await api.listCredentials('agent-1')
    expect(fetch).toHaveBeenCalledWith('/api/v1/identity/credentials?agent_id=agent-1', { headers: {} })
  })
})

describe('api.getPolicyStatus', () => {
  it('fetches policy status via GET', async () => {
    const status = { enabled: true, tools: [] }
    global.fetch = mockFetch(status)

    const result = await api.getPolicyStatus()
    expect(result).toEqual(status)
    expect(fetch).toHaveBeenCalledWith('/api/v1/policy/status', { headers: {} })
  })
})

describe('api.getPolicySuggestions', () => {
  it('fetches suggestions via POST', async () => {
    global.fetch = mockFetch([])

    await api.getPolicySuggestions()
    expect(fetch).toHaveBeenCalledWith('/api/v1/policy/suggestions', { method: 'POST', headers: {} })
  })
})

describe('auth token injection', () => {
  afterEach(() => {
    setAuthToken(null)
  })

  it('includes Authorization header when token is set', async () => {
    setAuthToken('test-jwt-token')
    global.fetch = mockFetch({ total_agents: 1 })

    await api.getFleetOverview()
    expect(fetch).toHaveBeenCalledWith('/api/v1/fleet/overview', {
      headers: { Authorization: 'Bearer test-jwt-token' },
    })
  })

  it('clears Authorization header when token is null', async () => {
    setAuthToken('token')
    setAuthToken(null)
    global.fetch = mockFetch({})

    await api.getFleetOverview()
    expect(fetch).toHaveBeenCalledWith('/api/v1/fleet/overview', {
      headers: {},
    })
  })
})

describe('subscribeAlerts', () => {
  let instances: Array<{ onmessage: ((e: { data: string }) => void) | null; onerror: ((e: Event) => void) | null; close: ReturnType<typeof vi.fn>; url: string }>

  beforeEach(() => {
    instances = []
    const MockEventSource = class {
      onmessage: ((e: { data: string }) => void) | null = null
      onerror: ((e: Event) => void) | null = null
      close = vi.fn()
      url: string
      constructor(url: string) {
        this.url = url
        instances.push(this)
      }
    }
    vi.stubGlobal('EventSource', MockEventSource)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('creates EventSource and returns cleanup function', () => {
    const unsub = subscribeAlerts(vi.fn())
    expect(instances).toHaveLength(1)
    expect(instances[0].url).toBe('/api/v1/alerts/stream')

    unsub()
    expect(instances[0].close).toHaveBeenCalled()
  })

  it('parses incoming alert messages', () => {
    const onAlert = vi.fn()
    subscribeAlerts(onAlert)

    const alert = { alert_id: 'a1', severity: 'critical' }
    instances[0].onmessage!({ data: JSON.stringify(alert) })

    expect(onAlert).toHaveBeenCalledWith(alert)
  })

  it('ignores malformed JSON', () => {
    const onAlert = vi.fn()
    subscribeAlerts(onAlert)

    instances[0].onmessage!({ data: 'not json{' })

    expect(onAlert).not.toHaveBeenCalled()
  })
})
