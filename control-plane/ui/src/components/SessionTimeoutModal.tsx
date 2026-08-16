import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import './SessionTimeoutModal.css'

// 15 minutes idle timeout standard (NIST / OWASP / PCI-DSS)
const IDLE_TIMEOUT_MS = 15 * 60 * 1000
// Show warning modal 2 minutes (120 seconds) before automatic logout
const WARNING_BEFORE_MS = 2 * 60 * 1000
const WARNING_THRESHOLD_MS = IDLE_TIMEOUT_MS - WARNING_BEFORE_MS

export default function SessionTimeoutModal() {
  const { authenticated, logout, checkSession } = useAuth()
  const navigate = useNavigate()

  const [showWarning, setShowWarning] = useState(false)
  const [secondsRemaining, setSecondsRemaining] = useState(Math.floor(WARNING_BEFORE_MS / 1000))

  const lastActivityRef = useRef<number>(Date.now())
  const warningActiveRef = useRef<boolean>(false)

  const handleExtendSession = async () => {
    warningActiveRef.current = false
    setShowWarning(false)
    lastActivityRef.current = Date.now()
    try {
      await checkSession()
    } catch {
      // Ignored
    }
  }

  const handleLogoutNow = () => {
    warningActiveRef.current = false
    setShowWarning(false)
    logout()
    navigate('/login')
  }

  useEffect(() => {
    if (!authenticated) {
      setShowWarning(false)
      warningActiveRef.current = false
      return
    }

    const activityEvents = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart']
    const handleUserActivity = () => {
      // Only reset activity timestamp if the warning modal is not currently open
      if (!warningActiveRef.current) {
        lastActivityRef.current = Date.now()
      }
    }

    activityEvents.forEach((ev) => {
      window.addEventListener(ev, handleUserActivity, { passive: true })
    })

    const interval = setInterval(() => {
      const idleDuration = Date.now() - lastActivityRef.current

      if (idleDuration >= IDLE_TIMEOUT_MS) {
        // Inactivity timeout exceeded -> trigger auto logout
        warningActiveRef.current = false
        setShowWarning(false)
        clearInterval(interval)
        logout()
        navigate('/login?reason=idle_timeout')
      } else if (idleDuration >= WARNING_THRESHOLD_MS) {
        // Inactivity entered warning window
        warningActiveRef.current = true
        setShowWarning(true)
        const remaining = Math.max(0, Math.ceil((IDLE_TIMEOUT_MS - idleDuration) / 1000))
        setSecondsRemaining(remaining)
      } else {
        if (warningActiveRef.current) {
          warningActiveRef.current = false
          setShowWarning(false)
        }
      }
    }, 1000)

    return () => {
      activityEvents.forEach((ev) => {
        window.removeEventListener(ev, handleUserActivity)
      })
      clearInterval(interval)
    }
  }, [authenticated, logout, navigate])

  if (!authenticated || !showWarning) {
    return null
  }

  const minutes = Math.floor(secondsRemaining / 60)
  const seconds = secondsRemaining % 60
  const formattedTime = `${minutes}:${seconds.toString().padStart(2, '0')}`

  return (
    <div className="session-modal-overlay">
      <div className="session-modal-container">
        <div className="session-modal-header">
          <div className="session-warning-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2.2">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
          </div>
          <div>
            <h3 className="session-modal-title">Session Inactivity Warning</h3>
            <p className="session-modal-subtitle">PCI-DSS / NIST Compliance Inactivity Guard</p>
          </div>
        </div>

        <div className="session-modal-body">
          <p>
            You have been inactive for over 13 minutes. For your security and zero-trust policy compliance, your session will automatically terminate in:
          </p>
          <div className="session-countdown-pill">
            <span className="session-countdown-number">{formattedTime}</span>
          </div>
        </div>

        <div className="session-modal-actions">
          <button
            type="button"
            className="session-btn-secondary"
            onClick={handleLogoutNow}
          >
            Sign Out Now
          </button>
          <button
            type="button"
            className="session-btn-primary"
            onClick={handleExtendSession}
          >
            Extend Session
          </button>
        </div>
      </div>
    </div>
  )
}
