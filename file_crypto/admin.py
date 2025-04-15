from django.contrib import admin
from .models import DeletedFile , EncryptionHistory

@admin.register(DeletedFile)
class DeletedFileAdmin(admin.ModelAdmin):
    list_display = ("filename", "deleted_at", "file")
    search_fields = ("filename",)
    ordering = ("-deleted_at",)


admin.site.register(EncryptionHistory)