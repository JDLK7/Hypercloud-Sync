package types

type File struct{
	Id		string `json:"id"`
	Name	string `json:"name"`
	Size	int64 `json:"size"`
}

type FilesResponse struct {
	Ok    bool `json:"ok"`
	Files []File `json:"files"`
}