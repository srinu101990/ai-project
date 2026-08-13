import { Component, StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

class ErrorBox extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <pre
          style={{
            color: '#fecaca',
            background: '#111827',
            padding: '1.5rem',
            whiteSpace: 'pre-wrap',
            fontFamily: 'Consolas, monospace',
          }}
        >
          CYBER_SENTINEL.AI UI error{'\n'}
          {String(this.state.error?.stack || this.state.error)}
        </pre>
      )
    }
    return this.props.children
  }
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ErrorBox>
      <App />
    </ErrorBox>
  </StrictMode>,
)
