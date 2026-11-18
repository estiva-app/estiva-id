import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import { DeviceApproval } from './DeviceApproval'
import { CrashOnPurpose, ErrorBoundary, startErrorReports } from './errorReports'
import './styles.css'

// A crash on these pages is reported, signed in or not, and shows a message instead of a blank page (PROD-4).
startErrorReports()

const root = document.getElementById('root')
if (!root) throw new Error('No #root element')

// The approval page for a bot's request stands alone: it needs no session, so it
// must not wait on — or bounce through — the account page's sign-in (PER-22).
const isDeviceApproval = window.location.pathname === '/device'

createRoot(root).render(
  <StrictMode>
    <ErrorBoundary>
      <CrashOnPurpose />
      {isDeviceApproval ? (
        <DeviceApproval initialCode={new URLSearchParams(window.location.search).get('code')} />
      ) : (
        <App />
      )}
    </ErrorBoundary>
  </StrictMode>,
)
