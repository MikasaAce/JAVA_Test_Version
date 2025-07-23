import torch
import torch.nn.functional as F
import torch.nn as nn
import math


# 前馈神经网络
class FeedForwardNetwork(nn.Module):
    def __init__(self, d_model, d_ff, dropout=0.1):
        super(FeedForwardNetwork, self).__init__()
        self.fc1 = nn.Linear(d_model, d_ff)
        self.fc2 = nn.Linear(d_ff, d_model)
        self.dropout = nn.Dropout(dropout)
        self.activation = nn.ReLU()

    def forward(self, x):
        out = self.fc1(x)
        out = self.activation(out)
        out = self.dropout(out)
        out = self.fc2(out)
        return out


class MultiHeadAttention(nn.Module):
    def __init__(self, d_model, num_heads):
        super(MultiHeadAttention, self).__init__()
        assert d_model % num_heads == 0, "d_model must be divisible by num_heads"  #d_model可以被num_heads整除

        self.d_model = d_model
        self.num_heads = num_heads
        self.head_dim = d_model // num_heads

        self.W_q = nn.Linear(d_model, d_model)
        self.W_k = nn.Linear(d_model, d_model)
        self.W_v = nn.Linear(d_model, d_model)
        self.fc = nn.Linear(d_model, d_model)

    def scaled_dot_product_attention(self, q, k, v, mask=None):
        # 计算注意力
        attn_logits = torch.matmul(q, k.transpose(-1, -2)) / math.sqrt(self.head_dim)
        if mask is not None:
            #如果存在掩码mask，将mask应用到注意力值上
            attn_logits = attn_logits.masked_fill(mask == 0, float('-inf'))
        #计算注意力权重
        attn_weights = F.softmax(attn_logits, dim=-1)
        #注意力权重对V进行加权求和
        output = torch.matmul(attn_weights, v)
        return output, attn_weights

    #将输入张量（Q, K, V）的维度从(batch_size, seq_len, d_model)重塑为(batch_size, num_heads, seq_len, head_dim)
    def split_heads(self, x, batch_size):
        x = x.view(batch_size, -1, self.num_heads, self.head_dim)
        return x.transpose(1, 2)

    def forward(self, query, key, value, mask=None):
        batch_size = query.size(0)

        #计算QKV向量
        Q = self.W_q(query)
        K = self.W_k(key)
        V = self.W_v(value)
        #将Q、K、V分割成多个头
        Q = self.split_heads(Q, batch_size)
        K = self.split_heads(K, batch_size)
        V = self.split_heads(V, batch_size)
        #计算注意力输出（attn_output）和注意力权重（attn_weights）
        attn_output, attn_weights = self.scaled_dot_product_attention(Q, K, V, mask)
        #将多头注意力输出合并到单个张量
        attn_output = attn_output.transpose(1, 2).contiguous().view(batch_size, -1, self.d_model)

        output = self.fc(attn_output)
        return output, attn_weights


class EncoderLayer(nn.Module):
    def __init__(self, d_model, num_heads, d_ff, dropout=0.1):
        super(EncoderLayer, self).__init__()
        self.mha = MultiHeadAttention(d_model, num_heads)
        self.ffn = FeedForwardNetwork(d_model, d_ff, dropout)
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x, mask):
        attn_output, _ = self.mha(x, x, x, mask)
        x = self.norm1(x + self.dropout(attn_output))
        ffn_output = self.ffn(x)
        x = self.norm2(x + self.dropout(ffn_output))
        return x


# 假设这是一个基于Transformer的分类模型
class Transformer(nn.Module):
    def __init__(self, d_model, num_heads, d_ff, num_layers, num_classes, dropout=0.1):
        super(Transformer, self).__init__()
        self.encoder_layers = nn.ModuleList(
            [EncoderLayer(d_model, num_heads, d_ff, dropout) for _ in range(num_layers)])
        self.pool = nn.AdaptiveAvgPool1d(1)  # 池化层，维度降为1
        self.fc = nn.Linear(d_model, num_classes)

    def forward(self, src, src_mask=None):
        src = src.unsqueeze(1)  # Add seq_len dimension: (batch_size, 1, d_model)
        for layer in self.encoder_layers:
            src = layer(src, src_mask)
        src = src.transpose(1, 2)
        src = self.pool(src)
        src = src.squeeze(-1)
        output = self.fc(src)
        return output
