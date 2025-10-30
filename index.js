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
  name: { type: String, required: true },
  login: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  imageURL: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('user', userSchema);

const categorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

const Category = mongoose.model('category', categorySchema);

const productSchema = new mongoose.Schema({
  name: {type: String, required: true},
  price: {type: Number, required: true},
  onSale: {type: String, required: false},
  salePrice: {type: Number, default: null},
  imageURL: {type: String, required: true},
  category: {type: mongoose.Schema.Types.ObjectId, ref: 'category', required: true },
  createdAt: {type: Date, default: Date.now},
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
}, { timestamps: true });

const Order = mongoose.model('order', orderSchema);

app.use(cors({
  origin: [
    'http://10.0.0.110:3001',
    'https://searchnatura-el.netlify.app',
  ],
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
}));

// Configuração do Multer
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'meu-projeto',
    allowed_formats: ['jpg', 'png', 'jpeg', 'gif'],
    public_id: (req, file) => `${Date.now()}-${path.parse(file.originalname).name}`
  },
});

const upload = multer({ storage });
// Register user
app.post('/user', upload.single('image'), async (req, res) => {
  try {
    const { name, login, password } = req.body;

    if (!name || !login || !password) {
      return res.status(400).json({ error: "Name, login and password are required" });
    }

    if (!req.file || !req.file.path) {
      return res.status(400).json({ error: "Profile image is required" });
    }

    const existingUser = await User.findOne({ login });
    if (existingUser) {
      return res.status(409).json({ error: "Login already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, login, password: hashedPassword, imageURL: req.file.path });

    await newUser.save();

    return res.status(201).json({
      message: "User created successfully",
      user: {
        _id: newUser._id,
        name: newUser.name,
        login: newUser.login,
        imageURL: newUser.imageURL,
      }
    });
  } catch (err) {
  console.error("Erro no cadastro:", err);
  if (err.name === 'MongoServerError' && err.code === 11000) {
    return res.status(409).json({ error: "Login já está em uso" });
  }
  return res.status(500).json({ error: err.message || "Internal server error" });
}
});


// Login user
app.post('/login', async (req, res) => {
  try {
    const { login, password } = req.body;

    if (!login || !password) {
      return res.status(400).json({ error: 'Login e senha são obrigatórios' });
    }

    const user = await User.findOne({ login });

    if (!user) {
      return res.status(401).json({ error: 'Login ou senha incorretos' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Login ou senha incorretos' });
    }

    // ✅ Geração do token JWT
    const token = jwt.sign(
      { userId: user._id },           // payload
      process.env.JWT_SECRET,         // chave secreta
      { expiresIn: '7d' }             // validade de 7 dias
    );

    // ✅ Retorna o token no JSON
    return res.status(200).json({
      message: 'Login bem-sucedido',
      token,
      user: {
        _id: user._id,
        login: user.login,
        name: user.name
        // outros campos públicos se necessário
      }
    });

  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ error: 'Erro interno no servidor' });
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

app.get('/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password'); // ignora senha
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    return res.status(200).json(user);
  } catch (err) {
    console.error('Erro ao buscar usuário autenticado:', err);
    return res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Edit User
app.patch('/user/:id', auth, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    const updates = { ...req.body };
    if (req.file && req.file.path) {
      updates.imageURL = req.file.path;
    }
    if (updates.password) {
      updates.password = await bcrypt.hash(updates.password, 10);
    }
    const updatedUser = await User.findOneAndUpdate(
      { _id: id },
      updates,
      { new: true } // retorna o usuário já atualizado
    ).select('-password'); // ignora senha
    if (!updatedUser) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    return res.status(200).json(updatedUser);
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err);
    return res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Get Categories
app.get('/categories', auth, async (req, res) => {
  try {
    const categories = await Category.find().sort({createdAt: 1});
    return res.status(200).json(categories);
  } catch (err) {
    return res.status(500).json(err);
  }
});

// Create Category
app.post('/category', auth, async (req, res) => {
  try {
    const { name } = req.body;
    const category = new Category({ name });
    await category.save();
    return res.status(201).json(category);
  } catch (err) {
    return res.status(500).json(err);
  }
});

app.delete('/category/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    await Category.findByIdAndDelete(id);
    return res.status(200).json({ message: "Categoria excluída com sucesso" });
  } catch (err) {
    return res.status(500).json({ error: "Erro ao excluir categoria", details: err });
  }
});

// Create Product - Upload Image to Cloudinary
app.post("/product", auth, upload.single("image"), async (req, res) => {
  try {
    const { name, price, category, onSale, salePrice } = req.body;

    if (!name || !price || !category) {
      return res.status(400).json({ error: "Campos obrigatórios ausentes" });
    }

    const newProductData = {
      name,
      price: Number(price),
      category,
      onSale: onSale === "true" || onSale === true,
    };

    // Se for promoção, define o preço promocional
    if (newProductData.onSale && salePrice) {
      newProductData.salePrice = Number(salePrice);
    }

    // Se enviou imagem → envia ao Cloudinary
    if (req.file && req.file.path) {
      const uploadResult = await cloudinary.uploader.upload(req.file.path, {
        folder: "products",
      });
      fs.unlinkSync(req.file.path); // remove o arquivo local
      newProductData.imageURL = uploadResult.secure_url;
    }

    // Cria o produto
    const newProduct = new Product(newProductData);
    await newProduct.save();

    return res.status(201).json({
      message: "Produto criado com sucesso!",
      product: newProduct,
    });
  } catch (err) {
    console.error("❌ Erro ao criar produto:", err);
    return res.status(500).json({ error: "Erro ao criar produto" });
  }
});

// Get Products
app.get('/products', auth, async (req, res) => {
  try {
    const products = await Product.aggregate([
      {
        $lookup: {
          from: 'categories', // nome da collection de categorias
          localField: 'category',
          foreignField: '_id',
          as: 'categoryData'
        }
      },
      { $unwind: '$categoryData' }, // transforma o array em objeto
      {
        $sort: {
          'categoryData.createdAt': 1, // ordem de criação da categoria
          'createdAt': 1               // ordem de criação do produto
        }
      }
    ]);

    return res.status(200).json(products);
  } catch (err) {
    console.error(err);
    return res.status(500).json(err);
  }
});


app.get('/product/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const product = await Product.findById(id).populate('category');
    if (!product) {
      return res.status(404).json({ error: 'Produto não encontrado' });
    }
    return res.status(200).json(product);
  } catch (err) {
    return res.status(500).json(err);
  }
});

// Get Products by Category
app.get('/products/category/:categoryId', auth, async (req, res) => {
  try {
    const { categoryId } = req.params;
    const products = await Product.find({ category: categoryId }).sort({createdAt: 1});
    return res.status(200).json(products);
  } catch (err) {
    return res.status(500).json(err);
  }
});

// Post Products
app.post("/product", auth, upload.single("image"), async (req, res) => {
  try {
    const { name, price, category, onSale, salePrice } = req.body;

    if (!name || !price || !category) {
      return res.status(400).json({ error: "Campos obrigatórios ausentes" });
    }

    const newProductData = {
      name,
      price: Number(price),
      category,
      onSale: onSale === "true" || onSale === true,
    };

    if (newProductData.onSale && salePrice) {
      newProductData.salePrice = Number(salePrice);
    }

    // 👉 Se está usando multer-storage-cloudinary:
    if (req.file && req.file.path) {
      newProductData.imageURL = req.file.path; // Cloudinary já fornece a URL segura aqui
    }

    const newProduct = new Product(newProductData);
    await newProduct.save();

    return res.status(201).json({
      message: "Produto criado com sucesso!",
      product: newProduct,
    });
  } catch (err) {
    console.error("❌ Erro ao criar produto:", err);
    return res.status(500).json({ error: "Erro ao criar produto", details: err.message });
  }
});



// Edit Product
app.patch('/product/:id', auth, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = {};

    if (req.body.name) updateData.name = req.body.name;
    if (req.body.price) updateData.price = Number(req.body.price);

    if (req.body.category) {
      if (mongoose.Types.ObjectId.isValid(req.body.category)) {
        updateData.category = req.body.category;
      }
    }

    // onSale e salePrice
    if (req.body.onSale !== undefined) {
      const isOnSale = req.body.onSale === 'true' || req.body.onSale === true;
      updateData.onSale = isOnSale ? "true" : "false";
      updateData.salePrice = isOnSale
        ? Number(req.body.salePrice)
        : updateData.price || Number(req.body.price); // fallback se preço alterado
    }

    if (req.file && req.file.path) {
      updateData.imageURL = req.file.path;
    }

    const updatedProduct = await Product.findByIdAndUpdate(id, updateData, {
      new: true,
      runValidators: true,
    });

    if (!updatedProduct) {
      return res.status(404).json({ error: 'Product not found' });
    }

    return res.status(200).json(updatedProduct);
  } catch (err) {
    console.error('❌ Erro ao atualizar produto:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});


// Delete Product
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

// Get Orders
app.get('/orders', async (req, res) => {
  try {
    const order = await Order.find().sort({createdAt: 1}).populate('userId').populate('tableId').populate('items.productId');
    return res.status(200).json(order);
  } catch (err) {
    return res.status(500).json(err);
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

    return res.status(201).json(orderDetails);  // Envia a resposta para o frontend
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


// Delete Order
app.delete('/order/:id', async (req, res) => {
try {
  const { id } = req.params;
  try {
    const deletedOrder = await Order.findByIdAndDelete(id);
    if (deletedOrder) {
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