import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import winston from 'winston';
import dotenv from 'dotenv';
import fs from 'fs-extra';
import path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

dotenv.config();

const execAsync = promisify(exec);

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Initialize Express app
const app = express();
const PORT = parseInt(process.env.PORT || '3003', 10);

// Storage configuration
const STORAGE_PATH = process.env.STORAGE_PATH || '/tmp/javari-builds';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE || '10485760'); // 10MB

// Ensure storage directory exists
fs.ensureDirSync(STORAGE_PATH);

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 2000,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// API Key authentication middleware
const authenticateAPI = (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || apiKey !== process.env.MCP_API_KEY) {
    logger.warn('Unauthorized API access attempt', {
      ip: req.ip,
      path: req.path
    });
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  next();
};

// Apply auth to all routes except health
app.use((req, res, next) => {
  if (req.path === '/health') {
    return next();
  }
  authenticateAPI(req, res, next);
});

// Security: validate and sanitize paths
function sanitizePath(inputPath: string, workspaceId: string): string {
  const workspace = path.join(STORAGE_PATH, workspaceId);
  const fullPath = path.join(workspace, inputPath);
  
  // Prevent directory traversal
  if (!fullPath.startsWith(workspace)) {
    throw new Error('Invalid path: directory traversal detected');
  }
  
  return fullPath;
}

// Allowed file extensions
const ALLOWED_EXTENSIONS = [
  '.ts', '.tsx', '.js', '.jsx', '.json', '.md', '.txt', '.html', '.css',
  '.env', '.gitignore', '.npmrc', '.yml', '.yaml', '.toml'
];

function isAllowedFile(filename: string): boolean {
  const ext = path.extname(filename).toLowerCase();
  return ALLOWED_EXTENSIONS.includes(ext);
}

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    storage: {
      path: STORAGE_PATH,
      available: true
    }
  });
});

// Create workspace (project directory)
app.post('/api/workspace/create', async (req: Request, res: Response) => {
  try {
    const { workspaceId } = req.body;
    
    if (!workspaceId) {
      return res.status(400).json({ error: 'Workspace ID is required' });
    }
    
    const workspace = path.join(STORAGE_PATH, workspaceId);
    
    await fs.ensureDir(workspace);
    
    logger.info('Workspace created', { workspaceId, path: workspace });
    
    res.json({
      success: true,
      workspace: {
        id: workspaceId,
        path: workspace
      }
    });
  } catch (error) {
    logger.error('Failed to create workspace', { error });
    res.status(500).json({
      error: 'Failed to create workspace',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Create file
app.post('/api/files/create', async (req: Request, res: Response) => {
  try {
    const { workspaceId, filePath, content } = req.body;
    
    if (!workspaceId || !filePath || content === undefined) {
      return res.status(400).json({
        error: 'Workspace ID, file path, and content are required'
      });
    }
    
    if (!isAllowedFile(filePath)) {
      return res.status(400).json({
        error: 'File type not allowed',
        allowedExtensions: ALLOWED_EXTENSIONS
      });
    }
    
    if (Buffer.byteLength(content, 'utf8') > MAX_FILE_SIZE) {
      return res.status(400).json({
        error: 'File size exceeds maximum',
        maxSize: MAX_FILE_SIZE
      });
    }
    
    const fullPath = sanitizePath(filePath, workspaceId);
    
    // Ensure directory exists
    await fs.ensureDir(path.dirname(fullPath));
    
    // Write file
    await fs.writeFile(fullPath, content, 'utf8');
    
    logger.info('File created', { workspaceId, filePath });
    
    res.json({
      success: true,
      file: {
        path: filePath,
        size: Buffer.byteLength(content, 'utf8')
      }
    });
  } catch (error) {
    logger.error('Failed to create file', { error });
    res.status(500).json({
      error: 'Failed to create file',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Read file
app.get('/api/files/read', async (req: Request, res: Response) => {
  try {
    const { workspaceId, filePath } = req.query;
    
    if (!workspaceId || !filePath) {
      return res.status(400).json({
        error: 'Workspace ID and file path are required'
      });
    }
    
    const fullPath = sanitizePath(filePath as string, workspaceId as string);
    
    const content = await fs.readFile(fullPath, 'utf8');
    
    res.json({
      success: true,
      file: {
        path: filePath,
        content
      }
    });
  } catch (error) {
    logger.error('Failed to read file', { error });
    res.status(500).json({
      error: 'Failed to read file',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Update file
app.put('/api/files/update', async (req: Request, res: Response) => {
  try {
    const { workspaceId, filePath, content } = req.body;
    
    if (!workspaceId || !filePath || content === undefined) {
      return res.status(400).json({
        error: 'Workspace ID, file path, and content are required'
      });
    }
    
    const fullPath = sanitizePath(filePath, workspaceId);
    
    // Create backup
    const backupPath = `${fullPath}.backup`;
    if (await fs.pathExists(fullPath)) {
      await fs.copy(fullPath, backupPath);
    }
    
    // Write new content
    await fs.writeFile(fullPath, content, 'utf8');
    
    logger.info('File updated', { workspaceId, filePath });
    
    res.json({
      success: true,
      file: {
        path: filePath,
        size: Buffer.byteLength(content, 'utf8'),
        backup: backupPath
      }
    });
  } catch (error) {
    logger.error('Failed to update file', { error });
    res.status(500).json({
      error: 'Failed to update file',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Delete file
app.delete('/api/files/delete', async (req: Request, res: Response) => {
  try {
    const { workspaceId, filePath } = req.body;
    
    if (!workspaceId || !filePath) {
      return res.status(400).json({
        error: 'Workspace ID and file path are required'
      });
    }
    
    const fullPath = sanitizePath(filePath, workspaceId);
    
    await fs.remove(fullPath);
    
    logger.info('File deleted', { workspaceId, filePath });
    
    res.json({
      success: true,
      message: 'File deleted successfully'
    });
  } catch (error) {
    logger.error('Failed to delete file', { error });
    res.status(500).json({
      error: 'Failed to delete file',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// List directory contents
app.get('/api/dirs/list', async (req: Request, res: Response) => {
  try {
    const { workspaceId, dirPath = '.' } = req.query;
    
    if (!workspaceId) {
      return res.status(400).json({ error: 'Workspace ID is required' });
    }
    
    const fullPath = sanitizePath(dirPath as string, workspaceId as string);
    
    const entries = await fs.readdir(fullPath, { withFileTypes: true });
    
    const files = await Promise.all(
      entries.map(async (entry) => {
        const entryPath = path.join(fullPath, entry.name);
        const stats = await fs.stat(entryPath);
        
        return {
          name: entry.name,
          type: entry.isDirectory() ? 'directory' : 'file',
          size: stats.size,
          modified: stats.mtime
        };
      })
    );
    
    res.json({
      success: true,
      directory: dirPath,
      contents: files
    });
  } catch (error) {
    logger.error('Failed to list directory', { error });
    res.status(500).json({
      error: 'Failed to list directory',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Validate TypeScript
app.post('/api/validate/typescript', async (req: Request, res: Response) => {
  try {
    const { workspaceId, files } = req.body;
    
    if (!workspaceId) {
      return res.status(400).json({ error: 'Workspace ID is required' });
    }
    
    const workspace = path.join(STORAGE_PATH, workspaceId);
    
    logger.info('Validating TypeScript', { workspaceId, fileCount: files?.length });
    
    // Run TypeScript compiler in check mode
    try {
      const { stdout, stderr } = await execAsync('npx tsc --noEmit', {
        cwd: workspace,
        timeout: 30000
      });
      
      res.json({
        success: true,
        valid: true,
        output: stdout
      });
    } catch (error: any) {
      // TypeScript errors are in stdout/stderr
      const errors = error.stdout || error.stderr;
      
      res.json({
        success: true,
        valid: false,
        errors: errors.split('\n').filter((line: string) => line.trim())
      });
    }
  } catch (error) {
    logger.error('Failed to validate TypeScript', { error });
    res.status(500).json({
      error: 'Failed to validate TypeScript',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Generate Next.js template
app.post('/api/template/nextjs', async (req: Request, res: Response) => {
  try {
    const { workspaceId, name, typescript = true } = req.body;
    
    if (!workspaceId || !name) {
      return res.status(400).json({
        error: 'Workspace ID and project name are required'
      });
    }
    
    const workspace = path.join(STORAGE_PATH, workspaceId);
    
    logger.info('Generating Next.js template', { workspaceId, name, typescript });
    
    // Create basic Next.js structure
    const template = {
      'package.json': JSON.stringify({
        name,
        version: '0.1.0',
        private: true,
        scripts: {
          dev: 'next dev',
          build: 'next build',
          start: 'next start'
        },
        dependencies: {
          next: '^14.0.4',
          react: '^18.2.0',
          'react-dom': '^18.2.0'
        },
        devDependencies: typescript ? {
          '@types/node': '^20.10.6',
          '@types/react': '^18.2.46',
          '@types/react-dom': '^18.2.18',
          'typescript': '^5.3.3'
        } : {}
      }, null, 2),
      '.gitignore': 'node_modules\n.next\n.env.local\ndist\n',
      'README.md': `# ${name}\n\nGenerated by Javari AI\n`,
      'tsconfig.json': typescript ? JSON.stringify({
        compilerOptions: {
          target: 'ES2022',
          lib: ['dom', 'dom.iterable', 'esnext'],
          allowJs: true,
          skipLibCheck: true,
          strict: true,
          noEmit: true,
          esModuleInterop: true,
          module: 'esnext',
          moduleResolution: 'bundler',
          resolveJsonModule: true,
          isolatedModules: true,
          jsx: 'preserve',
          incremental: true,
          paths: {
            '@/*': ['./src/*']
          }
        },
        include: ['next-env.d.ts', '**/*.ts', '**/*.tsx'],
        exclude: ['node_modules']
      }, null, 2) : null
    };
    
    // Write template files
    for (const [filePath, content] of Object.entries(template)) {
      if (content) {
        const fullPath = path.join(workspace, filePath);
        await fs.ensureDir(path.dirname(fullPath));
        await fs.writeFile(fullPath, content, 'utf8');
      }
    }
    
    logger.info('Next.js template generated', { workspaceId, name });
    
    res.json({
      success: true,
      message: 'Next.js template generated successfully',
      files: Object.keys(template).filter(k => template[k as keyof typeof template])
    });
  } catch (error) {
    logger.error('Failed to generate template', { error });
    res.status(500).json({
      error: 'Failed to generate template',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Clean workspace (delete all files)
app.delete('/api/workspace/clean', async (req: Request, res: Response) => {
  try {
    const { workspaceId } = req.body;
    
    if (!workspaceId) {
      return res.status(400).json({ error: 'Workspace ID is required' });
    }
    
    const workspace = path.join(STORAGE_PATH, workspaceId);
    
    await fs.remove(workspace);
    
    logger.warn('Workspace cleaned', { workspaceId });
    
    res.json({
      success: true,
      message: 'Workspace cleaned successfully'
    });
  } catch (error) {
    logger.error('Failed to clean workspace', { error });
    res.status(500).json({
      error: 'Failed to clean workspace',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Error handling middleware
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error('Unhandled error', {
    error: error.message,
    stack: error.stack,
    path: req.path
  });
  
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`File System MCP Server running on port ${PORT}`);
  logger.info('Storage path:', STORAGE_PATH);
  logger.info('Max file size:', MAX_FILE_SIZE, 'bytes');
});

export default app;
