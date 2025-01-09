package estargz

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// Graph 表示一个图结构
type Graph struct {
	N            int            // 顶点数量
	Adjacent     map[int][]Edge // 邻接表，存储顶点及其连接的边
	VertexValues []int          // 顶点的值
}

// Edge 表示图中的一条边
type Edge struct {
	Vertex int // 连接的顶点
	Value  int // 边的值
}

// NewGraph 创建一个新的图
func NewGraph(N int) *Graph {
	return &Graph{
		N:        N,
		Adjacent: make(map[int][]Edge),
	}
}

// Connect 连接两个顶点，并指定边的值
func (g *Graph) Connect(vertex1, vertex2, edgeValue int) {
	g.Adjacent[vertex1] = append(g.Adjacent[vertex1], Edge{Vertex: vertex2, Value: edgeValue})
	g.Adjacent[vertex2] = append(g.Adjacent[vertex2], Edge{Vertex: vertex1, Value: edgeValue})
}

// AssignVertexValues 尝试为顶点赋值，确保每条边的两个顶点值之和等于边的值
func (g *Graph) AssignVertexValues() bool {
	g.VertexValues = make([]int, g.N)
	for i := range g.VertexValues {
		g.VertexValues[i] = -1 // -1 表示未赋值
	}

	visited := make([]bool, g.N)

	// 遍历所有顶点，以未访问的顶点为根进行深度优先搜索
	for root := 0; root < g.N; root++ {
		if visited[root] {
			continue
		}

		// 将根顶点的值设置为 0
		g.VertexValues[root] = 0

		// 使用栈实现深度优先搜索
		type StackItem struct {
			Parent int
			Vertex int
		}
		stack := []StackItem{{Parent: -1, Vertex: root}}

		for len(stack) > 0 {
			// 弹出栈顶元素
			item := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			parent, vertex := item.Parent, item.Vertex

			visited[vertex] = true

			// 遍历当前顶点的邻接顶点
			skip := true
			for _, edge := range g.Adjacent[vertex] {
				neighbor, edgeValue := edge.Vertex, edge.Value

				// 跳过父顶点
				if skip && neighbor == parent {
					skip = false
					continue
				}

				if visited[neighbor] {
					// 如果邻接顶点已访问过，说明图是环状的
					return false
				}

				// 将邻接顶点压入栈
				stack = append(stack, StackItem{Parent: vertex, Vertex: neighbor})

				// 设置邻接顶点的值
				g.VertexValues[neighbor] = (edgeValue - g.VertexValues[vertex] + g.N) % g.N
			}
		}
	}

	// 检查所有顶点是否都已赋值
	for _, value := range g.VertexValues {
		if value < 0 {
			panic("顶点未赋值")
		}
	}

	// 图是无环的，所有顶点值已成功赋值
	return true
}

// IntSaltHash 是一个随机哈希函数生成器
type IntSaltHash struct {
	N    int      // 模数
	Salt []uint32 // 随机盐值
}

// NewIntSaltHash 创建一个新的 IntSaltHash 实例
func NewIntSaltHash(N int) *IntSaltHash {
	return &IntSaltHash{
		N:    N,
		Salt: []uint32{},
	}
}

// Hash 计算哈希值
func (h *IntSaltHash) Hash(parentId int, name string) int {
	byteArray := []byte(name) // 将字符串转换为字节数组

	// 如果盐值不足，生成更多的盐值
	for len(h.Salt) < len(byteArray)+8 {
		salt, _ := rand.Int(rand.Reader, big.NewInt(int64(h.N-1)))
		h.Salt = append(h.Salt, uint32(salt.Int64())+1)
	}

	// 计算 parentId 的哈希部分
	idSum := uint32(0)
	for i := 0; i < 8; i++ {
		byteI := (parentId >> (i * 8)) & 0xFF // 提取字节
		idSum += uint32(byteI) * h.Salt[i]    // 乘以盐值并累加
	}

	// 计算 name 的哈希部分
	nameSum := uint32(0)
	for i := 0; i < len(byteArray); i++ {
		nameSum += h.Salt[i+8] * uint32(byteArray[i]) // 乘以盐值并累加
	}

	// 返回最终的哈希值
	return int(((idSum + nameSum) % uint32(h.N)))
}

// generateHash 生成哈希函数和顶点值
func generateHash(keys []HashKey) (*IntSaltHash, *IntSaltHash, []int, error) {
	NK := len(keys)

	// 计算图的顶点数 NG
	NG := max(NK+1, int(float64(NK)*2))

	trial := 0 // 试验次数
	var G *Graph
	var f1 *IntSaltHash
	var f2 *IntSaltHash
	for {
		if trial > 0 {
			// 每次增加 20%
			NG = max(NG+1, NG+int(float64(NK)*0.2))
		}
		trial++

		if NG > 100*(NK+1) {
			return nil, nil, nil, fmt.Errorf("too many iteration")
		}

		// 创建图和哈希函数
		G = NewGraph(NG)
		f1 = NewIntSaltHash(NG)
		f2 = NewIntSaltHash(NG)

		// 连接图的顶点
		for hashval, key := range keys {
			nodid := int(key.NodeId)
			name := key.Name
			G.Connect(f1.Hash(nodid, name), f2.Hash(nodid, name), hashval)
		}

		// 尝试为顶点赋值
		if G.AssignVertexValues() {
			break
		}
	}
	// 验证哈希结果
	for hashval, key := range keys {
		nodeId := int(key.NodeId)
		name := key.Name
		expected := (G.VertexValues[f1.Hash(nodeId, name)] + G.VertexValues[f2.Hash(nodeId, name)]) % NG
		if hashval != expected {
			return nil, nil, nil, errors.New("hash validation failed")
		}
	}

	return f1, f2, G.VertexValues, nil
}

// max 返回两个整数中的最大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type HashKey struct {
	Name   string
	NodeId int32
}

func PerfectHash(keys []HashKey) (*HashMeta, error) {
	f1, f2, vertexValues, err := generateHash(keys)

	uint32vertexValues := []uint32{}
	for _, v := range vertexValues {
		uint32vertexValues = append(uint32vertexValues, uint32(v))
	}

	if err != nil {
		return nil, err
	}

	return &HashMeta{Salt1: f1.Salt, Salt2: f2.Salt, Graph: uint32vertexValues, Keys: keys}, err

}
