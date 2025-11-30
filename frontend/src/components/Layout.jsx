import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Zap, LogOut, ChevronDown } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';

export function Layout({ children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div style={styles.layout}>
      <header style={styles.header}>
        <div style={styles.headerInner}>
          <Link to="/" style={styles.logo}>
            <div style={styles.logoIcon}>
              <Zap size={20} strokeWidth={2.5} />
            </div>
            <span style={styles.logoText}>sniftran</span>
          </Link>

          <div style={styles.userSection} ref={dropdownRef}>
            <button
              style={styles.userButton}
              onClick={() => setDropdownOpen(!dropdownOpen)}
            >
              <div style={styles.avatar}>
                {(user?.first_name?.[0] || user?.email?.[0] || 'U').toUpperCase()}
              </div>
              <span style={styles.userName}>{user?.first_name || user?.email}</span>
              <ChevronDown size={16} style={{
                color: 'var(--text-muted)',
                transform: dropdownOpen ? 'rotate(180deg)' : 'rotate(0)',
                transition: 'transform 0.2s',
              }} />
            </button>

            {dropdownOpen && (
              <div style={styles.dropdown}>
                <div style={styles.dropdownHeader}>
                  <span style={styles.dropdownEmail}>{user?.email}</span>
                </div>
                <div style={styles.dropdownDivider} />
                <button style={styles.dropdownItem} onClick={handleLogout}>
                  <LogOut size={16} />
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main style={styles.main}>
        <div style={styles.container}>
          {children}
        </div>
      </main>
    </div>
  );
}

const styles = {
  layout: {
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
  },
  header: {
    borderBottom: '1px solid var(--border)',
    background: 'var(--bg-secondary)',
    position: 'sticky',
    top: 0,
    zIndex: 50,
  },
  headerInner: {
    maxWidth: '1200px',
    margin: '0 auto',
    padding: '0 24px',
    height: '64px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  logo: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    textDecoration: 'none',
    color: 'var(--text-primary)',
  },
  logoIcon: {
    width: '32px',
    height: '32px',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--accent)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'white',
  },
  logoText: {
    fontSize: '18px',
    fontWeight: '600',
    letterSpacing: '-0.3px',
  },
  userSection: {
    position: 'relative',
  },
  userButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '6px 10px 6px 6px',
    background: 'transparent',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    cursor: 'pointer',
    transition: 'border-color 0.15s',
  },
  avatar: {
    width: '28px',
    height: '28px',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '12px',
    fontWeight: '600',
  },
  userName: {
    fontSize: '14px',
    color: 'var(--text-primary)',
    fontWeight: '500',
  },
  dropdown: {
    position: 'absolute',
    top: 'calc(100% + 8px)',
    right: 0,
    width: '200px',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    boxShadow: 'var(--shadow-lg)',
    overflow: 'hidden',
  },
  dropdownHeader: {
    padding: '12px 14px',
  },
  dropdownEmail: {
    fontSize: '13px',
    color: 'var(--text-muted)',
  },
  dropdownDivider: {
    height: '1px',
    background: 'var(--border)',
  },
  dropdownItem: {
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '10px 14px',
    fontSize: '14px',
    color: 'var(--text-secondary)',
    background: 'transparent',
    border: 'none',
    cursor: 'pointer',
    transition: 'background 0.15s, color 0.15s',
  },
  main: {
    flex: 1,
    padding: '32px 24px',
  },
  container: {
    maxWidth: '1200px',
    margin: '0 auto',
  },
};
