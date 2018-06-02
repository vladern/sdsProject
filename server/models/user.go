package models

// User all user information
type User struct {
	Name      string     `json:"name"`
	Lastname  string     `json:"lastname"`
	Email     string     `json:"email"`
	Password  string     `json:"password,omitempty"`
	Role      string     `json:"role,omitempty"`
	Sal       string     `json:"sal,omitempty"`
	FilesInfo []FileInfo `json: "fileInfo"`
}
