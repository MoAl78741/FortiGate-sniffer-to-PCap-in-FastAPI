import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Mail, Lock, ArrowRight, Loader2, Zap } from 'lucide-react';

export function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = await login(email, password);
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error);
      }
    } catch {
      setError('An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      {/* Background gradient orbs */}
      <div style={styles.bgOrb1} />
      <div style={styles.bgOrb2} />

      <div style={styles.content}>
        {/* Logo */}
        <div style={styles.logoSection}>
          <div style={styles.logoIcon}>
            <Zap size={24} strokeWidth={2.5} />
          </div>
          <span style={styles.logoText}>sniftran</span>
        </div>

        {/* Card */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <h1 style={styles.title}>Welcome back</h1>
            <p style={styles.subtitle}>Enter your credentials to access your account</p>
          </div>

          <form style={styles.form} onSubmit={handleSubmit}>
            {error && (
              <div style={styles.error}>
                {error}
              </div>
            )}

            <div style={styles.fieldGroup}>
              <label style={styles.label}>Email</label>
              <div style={styles.inputWrapper}>
                <Mail size={18} style={styles.inputIcon} />
                <input
                  type="email"
                  placeholder="name@example.com"
                  style={styles.input}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
            </div>

            <div style={styles.fieldGroup}>
              <label style={styles.label}>Password</label>
              <div style={styles.inputWrapper}>
                <Lock size={18} style={styles.inputIcon} />
                <input
                  type="password"
                  placeholder="Enter your password"
                  style={styles.input}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              style={{
                ...styles.button,
                opacity: loading ? 0.7 : 1,
              }}
              disabled={loading}
            >
              {loading ? (
                <Loader2 size={18} className="animate-spin" />
              ) : (
                <>
                  Sign in
                  <ArrowRight size={18} />
                </>
              )}
            </button>
          </form>

          <div style={styles.footer}>
            <span style={styles.footerText}>Don't have an account?</span>
            <Link to="/signup" style={styles.link}>
              Create account
            </Link>
          </div>
        </div>

        <p style={styles.legal}>
          FortiGate sniffer capture to PCAP converter
        </p>
      </div>
    </div>
  );
}

const styles = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '24px',
    position: 'relative',
    overflow: 'hidden',
  },
  bgOrb1: {
    position: 'absolute',
    top: '-20%',
    right: '-10%',
    width: '600px',
    height: '600px',
    borderRadius: '50%',
    background: 'radial-gradient(circle, rgba(59, 130, 246, 0.15) 0%, transparent 70%)',
    pointerEvents: 'none',
  },
  bgOrb2: {
    position: 'absolute',
    bottom: '-20%',
    left: '-10%',
    width: '500px',
    height: '500px',
    borderRadius: '50%',
    background: 'radial-gradient(circle, rgba(139, 92, 246, 0.1) 0%, transparent 70%)',
    pointerEvents: 'none',
  },
  content: {
    width: '100%',
    maxWidth: '400px',
    position: 'relative',
    zIndex: 1,
  },
  logoSection: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '10px',
    marginBottom: '32px',
  },
  logoIcon: {
    width: '40px',
    height: '40px',
    borderRadius: 'var(--radius-md)',
    background: 'var(--accent)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'white',
  },
  logoText: {
    fontSize: '24px',
    fontWeight: '600',
    letterSpacing: '-0.5px',
  },
  card: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-xl)',
    padding: '32px',
    boxShadow: 'var(--shadow-lg)',
  },
  cardHeader: {
    marginBottom: '24px',
  },
  title: {
    fontSize: '24px',
    fontWeight: '600',
    marginBottom: '8px',
    letterSpacing: '-0.5px',
  },
  subtitle: {
    fontSize: '14px',
    color: 'var(--text-secondary)',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  error: {
    padding: '12px 16px',
    borderRadius: 'var(--radius-md)',
    background: 'var(--error-muted)',
    color: 'var(--error)',
    fontSize: '14px',
    border: '1px solid rgba(239, 68, 68, 0.2)',
  },
  fieldGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  label: {
    fontSize: '14px',
    fontWeight: '500',
    color: 'var(--text-primary)',
  },
  inputWrapper: {
    position: 'relative',
  },
  inputIcon: {
    position: 'absolute',
    left: '14px',
    top: '50%',
    transform: 'translateY(-50%)',
    color: 'var(--text-muted)',
    pointerEvents: 'none',
  },
  input: {
    width: '100%',
    padding: '12px 14px 12px 44px',
    fontSize: '14px',
    borderRadius: 'var(--radius-md)',
    border: '1px solid var(--border)',
    background: 'var(--bg-primary)',
    color: 'var(--text-primary)',
    outline: 'none',
    transition: 'border-color 0.15s, box-shadow 0.15s',
  },
  button: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    padding: '12px 20px',
    fontSize: '14px',
    fontWeight: '500',
    borderRadius: 'var(--radius-md)',
    border: 'none',
    background: 'var(--accent)',
    color: 'white',
    cursor: 'pointer',
    transition: 'background 0.15s, transform 0.1s',
    marginTop: '4px',
  },
  footer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
    marginTop: '24px',
    paddingTop: '24px',
    borderTop: '1px solid var(--border)',
  },
  footerText: {
    fontSize: '14px',
    color: 'var(--text-secondary)',
  },
  link: {
    fontSize: '14px',
    fontWeight: '500',
    color: 'var(--accent)',
    textDecoration: 'none',
  },
  legal: {
    marginTop: '24px',
    textAlign: 'center',
    fontSize: '13px',
    color: 'var(--text-muted)',
  },
};
