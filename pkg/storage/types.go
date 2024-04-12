package storage

type Result struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

type ProofResponse struct {
	Proof []byte `json:"proof"`
}

type ADNLProofResponse struct {
	Key       []byte `json:"key"`
	Signature []byte `json:"signature"`
}

type File struct {
	Index uint32 `json:"index"`
	Name  string `json:"name"`
	Size  uint64 `json:"size"`
}

type Peer struct {
	Addr          string `json:"addr"`
	ID            string `json:"id"`
	UploadSpeed   uint64 `json:"upload_speed"`
	DownloadSpeed uint64 `json:"download_speed"`
}

type BagDetailed struct {
	Bag
	BagPiecesNum  uint32 `json:"bag_pieces_num"`
	HasPiecesMask []byte `json:"has_pieces_mask"`
	Files         []File `json:"files"`
	Peers         []Peer `json:"peers"`

	PieceSize  uint32 `json:"piece_size"`
	BagSize    uint64 `json:"bag_size"`
	MerkleHash string `json:"merkle_hash"`
	Path       string `json:"path"`
}

type Bag struct {
	BagID         string `json:"bag_id"`
	Description   string `json:"description"`
	Downloaded    uint64 `json:"downloaded"`
	Size          uint64 `json:"size"`
	Peers         uint64 `json:"peers"`
	DownloadSpeed uint64 `json:"download_speed"`
	UploadSpeed   uint64 `json:"upload_speed"`
	FilesCount    uint64 `json:"files_count"`
	DirName       string `json:"dir_name"`
	Completed     bool   `json:"completed"`
	HeaderLoaded  bool   `json:"header_loaded"`
	InfoLoaded    bool   `json:"info_loaded"`
	Active        bool   `json:"active"`
	Seeding       bool   `json:"seeding"`
}

type List struct {
	Bags []Bag `json:"bags"`
}

type Created struct {
	BagID string `json:"bag_id"`
}
