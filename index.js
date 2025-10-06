const express = require('express');
const cors = require('cors');
require('dotenv').config();
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const port = 3000 || process.env.PORT;            
app.use(express.json());                                                                                  
mongoose.connect(process.env.DB_URI, {
  useNewUrlParser: true, 
  useUnifiedTopology: true }
)
.then(() => {
  console.log('✅ MongoDB conectado');

  // Somente agora iniciamos o servidor
  app.listen(port, () => console.log(`Server is running on http://localhost:${port}`));
})
.catch((err) => {
  console.error('❌ Erro ao conectar ao MongoDB:', err.message);
});

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('user', userSchema);

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  imageURL: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

const Product = mongoose.model('product', productSchema);

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true },
  items: [
      {
          productId: { type: mongoose.Schema.Types.ObjectId, ref: 'product', required: true },
          quantity: { type: Number, required: true },
      },
  ],
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'completed'], default: 'pending' },
});

const Order = mongoose.model('order', orderSchema);

app.use(cors({
  origin: [
    'http://10.0.0.110:3001',
    'https://searchnatura-el.netlify.app',
  ],
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Login user
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Email não encontrado' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Senha incorreta' });
    }

    // ✅ Geração do token JWT
    const token = jwt.sign(
      { userId: user._id },           // payload
      process.env.JWT_SECRET,         // chave secreta
      { expiresIn: '1d' }             // validade de 1 dia
    );

    // ✅ Retorna o token no JSON
    res.status(200).json({
      message: 'Login bem-sucedido',
      token,
      user: {
        _id: user._id,
        email: user.email,
        // outros campos públicos se necessário
      }
    });

  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Create User
app.post('/create', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Verifica se já existe usuário com esse email
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: "Email already in use" });
    }

    // Criptografa a senha antes de salvar
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    return res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error("Erro no cadastro:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

const auth = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    // Verifica se o token existe
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    // Tenta verificar e decodificar o token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Armazena o ID do usuário no request para acesso posterior
    req.userId = decoded.userId;
    next();
  } catch (err) {
    // Diferencia erros de token expirado e outros erros de token
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired. Please log in again.' });
    } else if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token. Access denied.' });
    } else {
      return res.status(400).json({ error: 'An error occurred during authentication.' });
    }
  }
};

// Configuração do Multer
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'meu-projeto', // Nome da pasta
    allowed_formats: ['jpg', 'png', 'jpeg', 'gif'],
    public_id: (req, file) => {
      const nameWithoutExt = path.parse(file.originalname).name; // remove extensão
      return `${Date.now()}-${nameWithoutExt}`; // nome único sem duplicar a extensão
    },
  },
});

const upload = multer({storage});

// Upload de imagem
app.post('/upload', auth, upload.single('image'), (req, res) => {
  try {
    if (!req.file || !req.file.path) {
      return res.status(400).json({ error: 'No file uploaded or upload failed' });
    }
    res.status(200).json({ imageURL: req.file.path });
  } catch (err) {
    console.error('Erro no upload:', err);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Create Product
// Rota Products
app.get('/products', auth, async (req, res) => {
  try {
    const products = await Product.find().sort({createdAt: 1});
    return res.status(200).json(products);
  } catch (err) {
    return res.status(500).json(err);
  }
});

// Get Products
app.get('/products', auth, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.status(200).json(products);
  } catch (err) {
    console.error('Erro ao buscar produtos:', err);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Post Products
app.post('/product', upload.single('image'), async (req, res) => {
  try {
    const { name, price } = req.body;

    if (!req.file || !req.file.path) {
      return res.status(400).json({ error: 'Imagem é obrigatória' });
    }

    const imageURL = req.file.path; // URL direta do Cloudinary

    const product = new Product({
      name,
      price,
      imageURL,
    });

    await product.save();
    res.status(201).json(product);
  } catch (error) {
    console.error('❌ Erro ao salvar produto:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/product/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;

    // Encontra o produto primeiro
    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ error: 'Produto não encontrado' });
    }

    // Remove a imagem do Cloudinary
    // Aqui assumimos que product.imageURL é algo como "meu-projeto/1758026546-nome.jpg"
    // Se tiver a URL completa, podemos extrair o public_id:
    const publicId = product.imageURL
      .split('/')
      .slice(-2)
      .join('/')
      .split('.')[0]; // remove a extensão

    await cloudinary.uploader.destroy(publicId);

    // Remove o produto do banco de dados
    await Product.findByIdAndDelete(id);

    return res.sendStatus(204);
  } catch (err) {
    console.error(err);
    return res.status(500).json(err);
  }
});

// Rota Orders
app.get('/orders', async (req, res) => {
  try {
    const order = await Order.find().sort({createdAt: 1}).populate('userId').populate('tableId').populate('items.productId');
    return res.status(200).json(order);
  } catch (err) {
    return res.status(500).json(err);
  }
});

// Get Orders by User
app.get('/orders', auth, async (req, res) => {
  try {
    const order = await Order.find().populate('userId').populate('tableId').populate('items.productId');
    

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    return res.status(200).json(order); // Retorna os dados da ordem
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Create Order
app.post('/order', auth, async (req, res) => {
  try {
    const order = req.body;
    if (order.items.length === 0) {
      return res.status(400).json('Continue sem pedir seu miseravi!');
    }

    const createdOrder = await Order.create(order);
    const orderDetails = await Order.findById(createdOrder._id)
      .populate('userId')
      .populate('tableId')
      .populate('items.productId');

    io.emit('orders@new', orderDetails);
    return res.status(201).json(orderDetails);  // Envia a resposta para o frontend
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Update Order - Toggle status between 'pending' and 'completed'
app.patch('/order/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;

    const updatedOrder = await Order.findOneAndUpdate(
      {_id: id},
      [
        {
          $set: {
            status: {
              $cond: { if: { $eq: ["$status", "pending"] }, then: "completed", else: "pending" },
            },
          },
        },
      ],
      { new: true } // Retorna o documento atualizado
    );
    
    
    const orderChecked = await Order.findById(updatedOrder._id).populate('userId').populate('tableId').populate('items.productId');
    if (!updatedOrder) {
      return res.status(404).json({ error: 'Order not found' });
    }
    

    io.emit('order@checked', orderChecked);

    return res.status(200).json(orderChecked);
  } catch (err) {
    res.status(500).json(err);
  }
});

// Delete Order
app.delete('/order/:id', async (req, res) => {
try {
  const { id } = req.params;
  try {
    const deletedOrder = await Order.findByIdAndDelete(id);
    if (deletedOrder) {
      io.emit('order@deleted', deletedOrder); // Certifique-se de que deletedOrder tem _id
      res.status(200).send(deletedOrder);
    } else {
      res.status(404).send({ error: 'Pedido não encontrado' });
    }
  } catch (error) {
    console.error('Erro ao deletar pedido:', error);
    res.status(500).send({ error: 'Erro no servidor' });
  }
  
} catch (err) {
  return res.status(500).json(err);
}
});