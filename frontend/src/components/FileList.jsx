import { useState } from 'react';
import {
  FileText, Download, RefreshCw, Trash2, Pencil,
  CheckCircle2, Clock, Loader2, MoreHorizontal, X
} from 'lucide-react';

export function FileList({ files, onConvert, onDelete, onRename }) {
  const [renameModal, setRenameModal] = useState({ open: false, file: null });
  const [newName, setNewName] = useState('');
  const [converting, setConverting] = useState(null);
  const [deleting, setDeleting] = useState(null);
  const [menuOpen, setMenuOpen] = useState(null);

  const handleConvert = async (file) => {
    setConverting(file.id);
    try {
      await onConvert(file.id);
    } finally {
      setConverting(null);
    }
  };

  const handleDelete = async (file) => {
    setMenuOpen(null);
    if (!confirm(`Delete "${file.content}"?`)) return;
    setDeleting(file.id);
    try {
      await onDelete(file.id);
    } finally {
      setDeleting(null);
    }
  };

  const openRename = (file) => {
    setMenuOpen(null);
    setNewName(file.content);
    setRenameModal({ open: true, file });
  };

  const handleRename = async () => {
    if (!newName.trim()) return;
    await onRename(renameModal.file.id, newName.trim());
    setRenameModal({ open: false, file: null });
    setNewName('');
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  if (files.length === 0) {
    return (
      <div style={styles.empty}>
        <div style={styles.emptyIcon}>
          <FileText size={32} />
        </div>
        <h3 style={styles.emptyTitle}>No files yet</h3>
        <p style={styles.emptyText}>Upload sniffer captures to get started</p>
      </div>
    );
  }

  return (
    <>
      <div style={styles.container}>
        <div style={styles.header}>
          <h2 style={styles.title}>Files</h2>
          <span style={styles.count}>{files.length}</span>
        </div>

        <div style={styles.list}>
          {files.map((file) => (
            <div key={file.id} style={styles.row}>
              <div style={styles.fileInfo}>
                <div style={styles.iconWrapper}>
                  <FileText size={18} />
                </div>
                <div style={styles.details}>
                  <span style={styles.fileName}>{file.content}</span>
                  <span style={styles.date}>{formatDate(file.date_created)}</span>
                </div>
              </div>

              <div style={styles.status}>
                {file.has_converted_data ? (
                  <span style={styles.statusConverted}>
                    <CheckCircle2 size={14} />
                    Converted
                  </span>
                ) : (
                  <span style={styles.statusPending}>
                    <Clock size={14} />
                    Pending
                  </span>
                )}
              </div>

              <div style={styles.actions}>
                <a
                  href={`/download/${file.id}`}
                  style={styles.actionBtn}
                  title="Download original"
                >
                  <Download size={16} />
                </a>

                {file.has_converted_data ? (
                  <a
                    href={`/download-pcap/${file.id}`}
                    style={{ ...styles.actionBtn, ...styles.actionBtnSuccess }}
                    title="Download PCAP"
                  >
                    <Download size={16} />
                  </a>
                ) : (
                  <button
                    style={styles.actionBtn}
                    onClick={() => handleConvert(file)}
                    disabled={converting === file.id}
                    title="Convert to PCAP"
                  >
                    {converting === file.id ? (
                      <Loader2 size={16} className="animate-spin" />
                    ) : (
                      <RefreshCw size={16} />
                    )}
                  </button>
                )}

                <div style={styles.menuWrapper}>
                  <button
                    style={styles.actionBtn}
                    onClick={() => setMenuOpen(menuOpen === file.id ? null : file.id)}
                  >
                    <MoreHorizontal size={16} />
                  </button>

                  {menuOpen === file.id && (
                    <div style={styles.menu}>
                      <button style={styles.menuItem} onClick={() => openRename(file)}>
                        <Pencil size={14} />
                        Rename
                      </button>
                      <button
                        style={{ ...styles.menuItem, ...styles.menuItemDanger }}
                        onClick={() => handleDelete(file)}
                      >
                        <Trash2 size={14} />
                        Delete
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Rename Modal */}
      {renameModal.open && (
        <div style={styles.modalOverlay} onClick={() => setRenameModal({ open: false, file: null })}>
          <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <h3 style={styles.modalTitle}>Rename file</h3>
              <button
                style={styles.modalClose}
                onClick={() => setRenameModal({ open: false, file: null })}
              >
                <X size={18} />
              </button>
            </div>
            <div style={styles.modalBody}>
              <label style={styles.label}>File name</label>
              <input
                type="text"
                style={styles.input}
                value={newName}
                onChange={(e) => setNewName(e.target.value.slice(0, 20))}
                maxLength={20}
                autoFocus
                onKeyDown={(e) => e.key === 'Enter' && newName.trim() && handleRename()}
              />
              <span style={styles.hint}>Maximum 20 characters</span>
            </div>
            <div style={styles.modalFooter}>
              <button
                style={styles.btnSecondary}
                onClick={() => setRenameModal({ open: false, file: null })}
              >
                Cancel
              </button>
              <button
                style={{
                  ...styles.btnPrimary,
                  opacity: !newName.trim() ? 0.5 : 1,
                }}
                onClick={handleRename}
                disabled={!newName.trim()}
              >
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

const styles = {
  container: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '16px 20px',
    borderBottom: '1px solid var(--border)',
  },
  title: {
    fontSize: '15px',
    fontWeight: '600',
  },
  count: {
    fontSize: '12px',
    fontWeight: '500',
    padding: '2px 8px',
    borderRadius: '9999px',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
  },
  list: {
    maxHeight: '400px',
    overflow: 'auto',
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: '16px',
    padding: '14px 20px',
    borderBottom: '1px solid var(--border)',
    transition: 'background 0.15s',
  },
  fileInfo: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    minWidth: 0,
  },
  iconWrapper: {
    width: '36px',
    height: '36px',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
  },
  details: {
    minWidth: 0,
  },
  fileName: {
    display: 'block',
    fontSize: '14px',
    fontWeight: '500',
    color: 'var(--text-primary)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  date: {
    fontSize: '12px',
    color: 'var(--text-muted)',
  },
  status: {
    flexShrink: 0,
  },
  statusConverted: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    fontSize: '12px',
    fontWeight: '500',
    padding: '4px 10px',
    borderRadius: '9999px',
    background: 'var(--success-muted)',
    color: 'var(--success)',
  },
  statusPending: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    fontSize: '12px',
    fontWeight: '500',
    padding: '4px 10px',
    borderRadius: '9999px',
    background: 'var(--warning-muted)',
    color: 'var(--warning)',
  },
  actions: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    flexShrink: 0,
  },
  actionBtn: {
    width: '32px',
    height: '32px',
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    background: 'transparent',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    textDecoration: 'none',
    transition: 'all 0.15s',
  },
  actionBtnSuccess: {
    borderColor: 'var(--success)',
    color: 'var(--success)',
  },
  menuWrapper: {
    position: 'relative',
  },
  menu: {
    position: 'absolute',
    top: 'calc(100% + 4px)',
    right: 0,
    width: '140px',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    boxShadow: 'var(--shadow-lg)',
    overflow: 'hidden',
    zIndex: 10,
  },
  menuItem: {
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '10px 14px',
    fontSize: '13px',
    color: 'var(--text-secondary)',
    background: 'transparent',
    border: 'none',
    cursor: 'pointer',
    textAlign: 'left',
  },
  menuItemDanger: {
    color: 'var(--error)',
  },
  empty: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: '64px 24px',
    textAlign: 'center',
  },
  emptyIcon: {
    width: '64px',
    height: '64px',
    borderRadius: 'var(--radius-lg)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-muted)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 20px',
  },
  emptyTitle: {
    fontSize: '16px',
    fontWeight: '600',
    marginBottom: '6px',
  },
  emptyText: {
    fontSize: '14px',
    color: 'var(--text-muted)',
  },
  modalOverlay: {
    position: 'fixed',
    inset: 0,
    background: 'rgba(0, 0, 0, 0.7)',
    backdropFilter: 'blur(4px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '24px',
    zIndex: 100,
  },
  modal: {
    width: '100%',
    maxWidth: '400px',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    overflow: 'hidden',
  },
  modalHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '16px 20px',
    borderBottom: '1px solid var(--border)',
  },
  modalTitle: {
    fontSize: '16px',
    fontWeight: '600',
  },
  modalClose: {
    width: '32px',
    height: '32px',
    borderRadius: 'var(--radius-sm)',
    border: 'none',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  modalBody: {
    padding: '20px',
  },
  label: {
    display: 'block',
    fontSize: '14px',
    fontWeight: '500',
    marginBottom: '8px',
  },
  input: {
    width: '100%',
    padding: '10px 14px',
    fontSize: '14px',
    borderRadius: 'var(--radius-md)',
    border: '1px solid var(--border)',
    background: 'var(--bg-primary)',
    color: 'var(--text-primary)',
    outline: 'none',
  },
  hint: {
    display: 'block',
    marginTop: '8px',
    fontSize: '12px',
    color: 'var(--text-muted)',
  },
  modalFooter: {
    display: 'flex',
    justifyContent: 'flex-end',
    gap: '10px',
    padding: '16px 20px',
    borderTop: '1px solid var(--border)',
    background: 'var(--bg-primary)',
  },
  btnSecondary: {
    padding: '10px 16px',
    fontSize: '14px',
    fontWeight: '500',
    borderRadius: 'var(--radius-md)',
    border: '1px solid var(--border)',
    background: 'transparent',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
  },
  btnPrimary: {
    padding: '10px 16px',
    fontSize: '14px',
    fontWeight: '500',
    borderRadius: 'var(--radius-md)',
    border: 'none',
    background: 'var(--accent)',
    color: 'white',
    cursor: 'pointer',
  },
};
