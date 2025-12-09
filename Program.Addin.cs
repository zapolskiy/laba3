// See https://raa.is/ImStudio/

using ImGuiNET;
using ClickableTransparentOverlay;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

partial class Program : Overlay
{
    /// <summary>
    /// преобразование тройки rgb в число для испольования в качстве цвета в ImGui
    /// </summary>
    /// <param name="r">red</param>
    /// <param name="g">green</param>
    /// <param name="b">blue</param>
    /// <returns>число содержащее инфрмацию о цвете, в подходящем для ImGui формате</returns>
    static uint rgb(int r, int g, int b) => (uint) (((r << 24) | (g << 16) | (b << 8) | 255) & 0xffffffffL);

    /// <summary>
    /// фоновое изображение
    /// </summary>
    Image<Rgba32> fone;

    nint fonehandle;

    /// <summary>
    /// конструктор
    /// </summary>
    public Program(int wd, int hg) : base(wd, hg)
    {
        ReplaceFont("Cousine-Regular.ttf", 28, FontGlyphRangeType.Cyrillic);

        Configuration configuration = Configuration.Default.Clone();
        configuration.PreferContiguousImageBuffers  = true;
        fone = new (configuration, wd, hg, Color.FromRgba(255,255,255,128));
    }

    /// <summary>
    /// точка запуска программы
    /// </summary>
    public static void Main()
    {
        new Program(1920, 1080).Start().Wait();
    }

    /// <summary>
    /// Отобразить фоновую текстуру
    /// </summary>
    /// <param name="withUpdate">обновить фоновую текстуру перед обновлениемы</param>
    public void ShowFone(bool withUpdate = false)
    {
        if (withUpdate)
            RemoveImage("fone");
        AddOrGetImagePointer("fone", fone, false, out fonehandle);
        ImGui.GetBackgroundDrawList().AddImage(fonehandle, new(0,0), new(fone.Width, fone.Height));
    }
}