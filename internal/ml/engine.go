// Package ml — ONNX Runtime inference for Sentinel-Pi
// Loads 6 models (binary + multiclass × LightGBM/XGBoost/CatBoost)
// with soft voting weights from config.json.
package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

// ═══════════════════════════════════════════════════════════════════════════
// Config — matches training config.json
// ═══════════════════════════════════════════════════════════════════════════

type Config struct {
	NumFeatures      int            `json:"num_features"`
	FeatureNames     []string       `json:"feature_names"`
	LabelMap         map[string]int `json:"label_map"`
	BinaryThreshold  float32        `json:"binary_threshold"`
	EnsembleWeights  []float32      `json:"ensemble_weights"`

	Binary struct {
		PerModelVal struct {
			LightGBM struct {
				Threshold float32 `json:"threshold"`
			} `json:"lightgbm"`
			XGBoost struct {
				Threshold float32 `json:"threshold"`
			} `json:"xgboost"`
			CatBoost struct {
				Threshold float32 `json:"threshold"`
			} `json:"catboost"`
		} `json:"per_model_val"`
		EnsembleWeights []float32 `json:"ensemble_weights"`
	} `json:"binary"`

	Multiclass struct {
		ModelsUsed      []string  `json:"models_used"`
		EnsembleWeights []float32 `json:"ensemble_weights"`
	} `json:"multiclass"`
}

// ═══════════════════════════════════════════════════════════════════════════
// Prediction result
// ═══════════════════════════════════════════════════════════════════════════

type Prediction struct {
	IsAttack       bool               `json:"is_attack"`
	AttackProb     float32            `json:"attack_prob"`
	AttackType     string             `json:"attack_type,omitempty"`
	ClassProbs     map[string]float32 `json:"class_probs,omitempty"`
	BinaryPerModel map[string]float32 `json:"binary_per_model"`
	Threshold      float32            `json:"threshold_used"`
}

// ═══════════════════════════════════════════════════════════════════════════
// Scaler — RobustScaler params exported from sklearn
// ═══════════════════════════════════════════════════════════════════════════

type Scaler struct {
	Center []float32 `json:"center"`
	Scale  []float32 `json:"scale"`
}

func (s *Scaler) Transform(x []float32) []float32 {
	if len(s.Center) == 0 {
		return x // no scaler loaded
	}
	out := make([]float32, len(x))
	for i := range x {
		if i < len(s.Center) && s.Scale[i] != 0 {
			out[i] = (x[i] - s.Center[i]) / s.Scale[i]
		} else {
			out[i] = x[i]
		}
	}
	return out
}

// ═══════════════════════════════════════════════════════════════════════════
// Engine
// ═══════════════════════════════════════════════════════════════════════════

type Engine struct {
	cfg    *Config
	scaler *Scaler

	// Binary models
	lgbBinary *ort.DynamicAdvancedSession
	xgbBinary *ort.DynamicAdvancedSession
	catBinary *ort.DynamicAdvancedSession

	// Multiclass models
	lgbMulti *ort.DynamicAdvancedSession
	xgbMulti *ort.DynamicAdvancedSession
	catMulti *ort.DynamicAdvancedSession

	labels []string // index -> label name
	mu     sync.Mutex
}

// NewEngine loads all models from the given directory.
// Expected files:
//   - config.json
//   - scaler.json (exported from joblib)
//   - lgb_binary.onnx, xgb_binary.onnx, cat_binary.onnx
//   - lgb_multiclass.onnx, xgb_multiclass.onnx, cat_multiclass.onnx
func NewEngine(modelsDir string) (*Engine, error) {
	// Load config
	cfgBytes, err := os.ReadFile(filepath.Join(modelsDir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Load scaler (optional - needs separate export step from joblib)
	scaler := &Scaler{}
	if b, err := os.ReadFile(filepath.Join(modelsDir, "scaler.json")); err == nil {
		json.Unmarshal(b, scaler)
	}

	// Init ONNX runtime
	if !ort.IsInitialized() {
		if err := ort.InitializeEnvironment(); err != nil {
			return nil, fmt.Errorf("init onnx: %w", err)
		}
	}

	// Build label index from map
	labels := make([]string, len(cfg.LabelMap))
	for name, idx := range cfg.LabelMap {
		if idx < len(labels) {
			labels[idx] = name
		}
	}

	e := &Engine{cfg: &cfg, scaler: scaler, labels: labels}

	// Load binary models
	binModels := []struct {
		file string
		dst  **ort.DynamicAdvancedSession
	}{
		{"lgb_binary.onnx", &e.lgbBinary},
		{"xgb_binary.onnx", &e.xgbBinary},
		{"cat_binary.onnx", &e.catBinary},
		{"lgb_multiclass.onnx", &e.lgbMulti},
		{"xgb_multiclass.onnx", &e.xgbMulti},
		{"cat_multiclass.onnx", &e.catMulti},
	}

	for _, m := range binModels {
		path := filepath.Join(modelsDir, m.file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue // skip missing model; still usable
		}
		sess, err := ort.NewDynamicAdvancedSession(path,
			[]string{"float_input"}, // onnxmltools default input name
			[]string{"label", "probabilities"},
			nil,
		)
		if err != nil {
			// Try alternate input name
			sess, err = ort.NewDynamicAdvancedSession(path,
				[]string{"input"},
				[]string{"label", "probabilities"},
				nil,
			)
			if err != nil {
				return nil, fmt.Errorf("load %s: %w", m.file, err)
			}
		}
		*m.dst = sess
	}

	return e, nil
}

// Predict runs ensemble inference on a feature vector
func (e *Engine) Predict(features []float32) (*Prediction, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(features) != e.cfg.NumFeatures {
		return nil, fmt.Errorf("feature count mismatch: got %d want %d",
			len(features), e.cfg.NumFeatures)
	}

	// Scale
	scaled := e.scaler.Transform(features)

	// Binary ensemble
	probs := make(map[string]float32)
	if p, err := e.runBinary(e.lgbBinary, scaled); err == nil {
		probs["lightgbm"] = p
	}
	if p, err := e.runBinary(e.xgbBinary, scaled); err == nil {
		probs["xgboost"] = p
	}
	if p, err := e.runBinary(e.catBinary, scaled); err == nil {
		probs["catboost"] = p
	}

	// Weighted soft voting for binary
	w := e.cfg.Binary.EnsembleWeights
	if len(w) < 3 {
		w = []float32{0.33, 0.33, 0.34}
	}
	binProb := w[0]*probs["lightgbm"] + w[1]*probs["xgboost"] + w[2]*probs["catboost"]

	result := &Prediction{
		IsAttack:       binProb >= e.cfg.BinaryThreshold,
		AttackProb:     binProb,
		BinaryPerModel: probs,
		Threshold:      e.cfg.BinaryThreshold,
	}

	// If classified as attack, run multiclass
	if result.IsAttack && len(e.labels) > 0 {
		classProbs := e.runMulticlass(scaled)
		if classProbs != nil {
			result.ClassProbs = classProbs

			// Find top class
			var topName string
			var topProb float32
			for name, p := range classProbs {
				if name == "benign" {
					continue // not interested in benign in multiclass prediction
				}
				if p > topProb {
					topProb = p
					topName = name
				}
			}
			result.AttackType = topName
		}
	}

	return result, nil
}

// runBinary executes a single binary model and returns P(attack)
func (e *Engine) runBinary(sess *ort.DynamicAdvancedSession, features []float32) (float32, error) {
	if sess == nil {
		return 0, fmt.Errorf("session nil")
	}

	shape := ort.NewShape(1, int64(len(features)))
	inputTensor, err := ort.NewTensor(shape, features)
	if err != nil {
		return 0, err
	}
	defer inputTensor.Destroy()

	outputs := make([]ort.Value, 2)
	if err := sess.Run([]ort.Value{inputTensor}, outputs); err != nil {
		return 0, err
	}
	defer func() {
		for _, o := range outputs {
			if o != nil {
				o.Destroy()
			}
		}
	}()

	// ZipMap output — extract class 1 probability
	if pt, ok := outputs[1].(*ort.Tensor[float32]); ok {
		data := pt.GetData()
		if len(data) >= 2 {
			return data[1], nil
		}
		if len(data) == 1 {
			return data[0], nil
		}
	}
	return 0, fmt.Errorf("unexpected output type")
}

// runMulticlass returns map of class name -> probability
func (e *Engine) runMulticlass(features []float32) map[string]float32 {
	probs := make(map[string]float32, len(e.labels))

	// Collect from each model
	type result struct {
		weight float32
		probs  []float32
	}
	var results []result

	weights := e.cfg.Multiclass.EnsembleWeights
	if len(weights) < 3 {
		weights = []float32{0.33, 0.33, 0.34}
	}

	for i, sess := range []*ort.DynamicAdvancedSession{e.lgbMulti, e.xgbMulti, e.catMulti} {
		if sess == nil || weights[i] == 0 {
			continue
		}
		p := e.runMulticlassSingle(sess, features)
		if p != nil {
			results = append(results, result{weights[i], p})
		}
	}

	if len(results) == 0 {
		return nil
	}

	// Weighted average
	total := float32(0)
	for _, r := range results {
		total += r.weight
	}
	for i, name := range e.labels {
		sum := float32(0)
		for _, r := range results {
			if i < len(r.probs) {
				sum += r.weight * r.probs[i]
			}
		}
		probs[name] = sum / total
	}

	return probs
}

func (e *Engine) runMulticlassSingle(sess *ort.DynamicAdvancedSession, features []float32) []float32 {
	shape := ort.NewShape(1, int64(len(features)))
	inputTensor, err := ort.NewTensor(shape, features)
	if err != nil {
		return nil
	}
	defer inputTensor.Destroy()

	outputs := make([]ort.Value, 2)
	if err := sess.Run([]ort.Value{inputTensor}, outputs); err != nil {
		return nil
	}
	defer func() {
		for _, o := range outputs {
			if o != nil {
				o.Destroy()
			}
		}
	}()

	if pt, ok := outputs[1].(*ort.Tensor[float32]); ok {
		return pt.GetData()
	}
	return nil
}

// Close releases all resources
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range []*ort.DynamicAdvancedSession{
		e.lgbBinary, e.xgbBinary, e.catBinary,
		e.lgbMulti, e.xgbMulti, e.catMulti,
	} {
		if s != nil {
			s.Destroy()
		}
	}
	return nil
}

// GetConfig returns loaded configuration
func (e *Engine) GetConfig() *Config { return e.cfg }
