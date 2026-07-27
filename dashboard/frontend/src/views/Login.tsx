import { useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import './Login.css'

export default function Login() {
  const { login, error } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    await login(email, password)
  }

  return (
    <div className="login-container">
      <div className="login-card glass">
        <h2>AgentWall Login</h2>
        <p>Enter your credentials or bootstrap token</p>
        
        {error && <div className="login-error">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Email</label>
            <input 
              type="text" 
              value={email} 
              onChange={e => setEmail(e.target.value)}
              placeholder="admin"
              required 
            />
          </div>
          <div className="form-group">
            <label>Password or Token</label>
            <input 
              type="password" 
              value={password} 
              onChange={e => setPassword(e.target.value)}
              required 
            />
          </div>
          <button type="submit" className="login-btn">Sign In</button>
        </form>
      </div>
    </div>
  )
}
