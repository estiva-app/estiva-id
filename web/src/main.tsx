import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import { DeviceApproval } from './DeviceApproval'
import './styles.css'

const root = document.getElementById('root')
if (!root) throw new Error('No #root element')

// The approval page for a bot's request stands alone: it needs no session, so it
// must not wait on — or bounce through — the account page's sign-in (PER-22).
const isDeviceApproval = window.location.pathname === '/device'

createRoot(root).render(
  <StrictMode>
    {isDeviceApproval ? (
      <DeviceApproval initialCode={new URLSearchParams(window.location.search).get('code')} />
    ) : (
      <App />
    )}
  </StrictMode>,
)
