import { useState, useEffect } from 'react';
import { Layout } from '../components/Layout';
import { FileUpload } from '../components/FileUpload';
import { FileList } from '../components/FileList';

export function Dashboard() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchFiles = async () => {
    try {
      const response = await fetch('/api/conversions', { credentials: 'same-origin' });
      if (response.ok) {
        const data = await response.json();
        setFiles(data);
      }
    } catch (error) {
      console.error('Failed to fetch files:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleUpload = async (uploadFiles) => {
    const formData = new FormData();
    uploadFiles.forEach((file) => formData.append('files', file));

    try {
      const response = await fetch('/upload/', {
        method: 'POST',
        credentials: 'same-origin',
        body: formData,
      });

      if (response.ok || response.redirected) {
        await fetchFiles();
      }
    } catch (error) {
      console.error('Upload failed:', error);
    }
  };

  const handleConvert = async (id) => {
    try {
      const response = await fetch(`/convert/${id}`, { credentials: 'same-origin' });
      if (response.ok || response.redirected) {
        await fetchFiles();
      }
    } catch (error) {
      console.error('Conversion failed:', error);
    }
  };

  const handleDelete = async (id) => {
    try {
      const response = await fetch(`/delete/${id}`, { credentials: 'same-origin' });
      if (response.ok || response.redirected) {
        await fetchFiles();
      }
    } catch (error) {
      console.error('Delete failed:', error);
    }
  };

  const handleRename = async (id, newName) => {
    try {
      const response = await fetch(`/rename/${id}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ new_name: newName }),
      });

      if (response.ok) {
        await fetchFiles();
      }
    } catch (error) {
      console.error('Rename failed:', error);
    }
  };

  return (
    <Layout>
      <div style={styles.header}>
        <h1 style={styles.title}>Convert Sniffer Captures</h1>
        <p style={styles.subtitle}>
          Upload FortiGate sniffer output files and convert them to Wireshark-compatible PCAP format
        </p>
      </div>

      <FileUpload onUpload={handleUpload} />

      {loading ? (
        <div style={styles.loading}>
          <div style={styles.spinner} />
          <span>Loading files...</span>
        </div>
      ) : (
        <FileList
          files={files}
          onConvert={handleConvert}
          onDelete={handleDelete}
          onRename={handleRename}
        />
      )}
    </Layout>
  );
}

const styles = {
  header: {
    marginBottom: '32px',
  },
  title: {
    fontSize: '28px',
    fontWeight: '600',
    letterSpacing: '-0.5px',
    marginBottom: '8px',
  },
  subtitle: {
    fontSize: '15px',
    color: 'var(--text-secondary)',
    lineHeight: '1.5',
  },
  loading: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '16px',
    padding: '64px 24px',
    color: 'var(--text-muted)',
    fontSize: '14px',
  },
  spinner: {
    width: '32px',
    height: '32px',
    border: '3px solid var(--border)',
    borderTopColor: 'var(--accent)',
    borderRadius: '50%',
    animation: 'spin 0.8s linear infinite',
  },
};
