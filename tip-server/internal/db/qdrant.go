package db

import (
	"context"
	"fmt"

	pb "github.com/qdrant/go-client/qdrant"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"tip-server/internal/config"
)

// QdrantClient wraps the Qdrant gRPC connection
// This is a stub for Phase 2 implementation
type QdrantClient struct {
	conn           *grpc.ClientConn
	pointsClient   pb.PointsClient
	collectionsClient pb.CollectionsClient
	cfg            config.QdrantConfig
	initialized    bool
}

// NewQdrantClient creates a new Qdrant client (Phase 2 stub)
func NewQdrantClient(cfg config.QdrantConfig) (*QdrantClient, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.GRPCPort)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Warn().
			Err(err).
			Str("addr", addr).
			Msg("Failed to connect to Qdrant (Phase 2 feature) - continuing without vector search")
		return &QdrantClient{cfg: cfg, initialized: false}, nil
	}

	client := &QdrantClient{
		conn:              conn,
		pointsClient:      pb.NewPointsClient(conn),
		collectionsClient: pb.NewCollectionsClient(conn),
		cfg:               cfg,
		initialized:       true,
	}

	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.GRPCPort).
		Msg("Connected to Qdrant (Phase 2 ready)")

	return client, nil
}

// Close closes the Qdrant connection
func (q *QdrantClient) Close() error {
	if q.conn != nil {
		return q.conn.Close()
	}
	return nil
}

// IsInitialized returns whether the client is connected
func (q *QdrantClient) IsInitialized() bool {
	return q.initialized
}

// ========== Phase 2 Stub Methods ==========
// These methods are placeholders for future vector search implementation

// CreateCollection creates a new vector collection (Phase 2)
func (q *QdrantClient) CreateCollection(ctx context.Context, name string, vectorSize uint64) error {
	if !q.initialized {
		return fmt.Errorf("qdrant client not initialized")
	}

	// TODO: Phase 2 implementation
	// _, err := q.collectionsClient.Create(ctx, &pb.CreateCollection{
	// 	CollectionName: name,
	// 	VectorsConfig: &pb.VectorsConfig{
	// 		Config: &pb.VectorsConfig_Params{
	// 			Params: &pb.VectorParams{
	// 				Size:     vectorSize,
	// 				Distance: pb.Distance_Cosine,
	// 			},
	// 		},
	// 	},
	// })

	log.Debug().Str("collection", name).Msg("CreateCollection called (Phase 2 stub)")
	return nil
}

// UpsertVectors upserts vectors into a collection (Phase 2)
func (q *QdrantClient) UpsertVectors(ctx context.Context, collection string, ids []uint64, vectors [][]float32, payloads []map[string]interface{}) error {
	if !q.initialized {
		return fmt.Errorf("qdrant client not initialized")
	}

	// TODO: Phase 2 implementation
	// Implement vector upsert logic using q.pointsClient.Upsert()

	log.Debug().
		Str("collection", collection).
		Int("count", len(ids)).
		Msg("UpsertVectors called (Phase 2 stub)")

	return nil
}

// SearchSimilar searches for similar vectors (Phase 2)
func (q *QdrantClient) SearchSimilar(ctx context.Context, collection string, vector []float32, limit uint64) ([]VectorSearchResult, error) {
	if !q.initialized {
		return nil, fmt.Errorf("qdrant client not initialized")
	}

	// TODO: Phase 2 implementation
	// Implement vector search using q.pointsClient.Search()

	log.Debug().
		Str("collection", collection).
		Uint64("limit", limit).
		Msg("SearchSimilar called (Phase 2 stub)")

	return nil, nil
}

// VectorSearchResult represents a search result from Qdrant (Phase 2)
type VectorSearchResult struct {
	ID      uint64                 `json:"id"`
	Score   float32                `json:"score"`
	Payload map[string]interface{} `json:"payload"`
}

// ========== Future Phase 2 Features ==========
// - Domain embedding for fuzzy domain matching
// - Text embedding for ransom note / threat report matching
// - Similar IOC detection based on context
// - Malware family clustering
